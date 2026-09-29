/// The password generator.
///
/// The daemon assembles the password itself: the randomness comes from the
/// system rather than the webview, and the value is put on the clipboard by the
/// same code that puts the vault's passwords there — so it is cleared by the
/// same rules.
import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Alert, Icon } from "../ui";
import { t } from "../i18n";
import { useEphemeral } from "../ephemeral";
import { invokeSecret } from "../seal";

/// The history as the daemon shows it: a length per password, no value.
type HistoryView = { made: number[]; taken: number[] };

export type Spec = {
  length: number;
  upper: boolean;
  lower: boolean;
  digits: boolean;
  symbols: boolean;
  avoid_ambiguous: boolean;
  symbols_inside_only: boolean;
};

/// Ready-made sets for other people's demands on a password.
///
/// "Digits only" and "letters only" turn up in bank forms and old panels more
/// often than one would like, and assembling them with switches every time is
/// work a machine does better.
const PRESETS: { key: string; spec: Partial<Spec> }[] = [
  { key: "all", spec: { upper: true, lower: true, digits: true, symbols: true } },
  { key: "alnum", spec: { upper: true, lower: true, digits: true, symbols: false } },
  { key: "letters", spec: { upper: true, lower: true, digits: false, symbols: false } },
  { key: "digits", spec: { upper: false, lower: false, digits: true, symbols: false } },
];

function matches(spec: Spec, preset: Partial<Spec>): boolean {
  return (Object.keys(preset) as (keyof Spec)[]).every((k) => spec[k] === preset[k]);
}

export const DEFAULT_SPEC: Spec = {
  length: 16,
  upper: true,
  lower: true,
  digits: true,
  symbols: true,
  avoid_ambiguous: true,
  symbols_inside_only: false,
};

const LENGTHS = [12, 16, 24, 32];

/// The strength in bits, by the same formula as in the daemon: the length
/// times the logarithm of the alphabet. It is computed here as well so that the
/// slider answers at once without a round trip.
export function bits(spec: Spec): number {
  const sizes = [
    [spec.upper, spec.avoid_ambiguous ? 23 : 26],
    [spec.lower, spec.avoid_ambiguous ? 24 : 26],
    [spec.digits, spec.avoid_ambiguous ? 8 : 10],
    [spec.symbols, 27],
  ] as [boolean, number][];
  const alphabet = sizes.reduce((sum, [on, n]) => sum + (on ? n : 0), 0);
  return alphabet > 1 ? Math.round(Math.log2(alphabet) * spec.length) : 0;
}

export function strength(n: number): "weak" | "fair" | "good" | "strong" {
  if (n < 50) return "weak";
  if (n < 70) return "fair";
  if (n < 100) return "good";
  return "strong";
}

export function GeneratorScreen({ onCopied }: { onCopied: (text: string) => void }) {
  const [spec, setSpec] = useState<Spec>(DEFAULT_SPEC);
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  // Lengths only: the values stay in the daemon, which also remembers every
  // password it makes — the window no longer sends one back.
  const [view, setView] = useState<HistoryView>({ made: [], taken: [] });
  const refresh = useCallback(() => {
    void invoke<HistoryView>("generator_history").then(setView).catch(() => {});
  }, []);

  const make = useCallback(
    async (next: Spec) => {
      try {
        setValue(await invokeSecret("generate_password", { spec: next }));
        setError(null);
        refresh();
      } catch (e) {
        setError(String(e));
      }
    },
    [refresh],
  );

  useEffect(() => {
    // The history lies in the daemon encrypted with the vault's key: a locked
    // vault means no history, and rightly so.
    void make(spec);
    // Only on the first showing: after that the password changes at the button
    // and at edits.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const patch = (change: Partial<Spec>) => {
    const next = { ...spec, ...change };
    setSpec(next);
    void make(next);
  };

  // The shown password is the history's first: copied from there by the
  // daemon, which also files it under "copied".
  const copyAt = async (taken: boolean, index: number) => {
    try {
      await invoke<number>("copy_generated", { taken, index });
      onCopied(t("action.copied"));
      refresh();
    } catch (e) {
      setError(String(e));
    }
  };
  const copy = () => copyAt(false, 0);

  const n = bits(spec);
  const level = strength(n);

  return (
    <div className="form wide">
      <div className="readout">
        <output className="mono">{value || "…"}</output>
        <span className="acts">
          <button type="button" className="btn icon-only" onClick={() => void make(spec)} title={t("gen.again")}>
            <Icon name="sync" size={14} />
          </button>
          <button type="button" className="btn primary" onClick={() => void copy()} disabled={!value}>
            <Icon name="copy" size={13} />
            {t("action.copy")}
          </button>
        </span>
      </div>

      <div className={`meter ${level}`}>
        <span style={{ width: `${Math.min(100, (n / 128) * 100)}%` }} />
      </div>
      <span className="hint">{t(`gen.strength.${level}`)} · {t("gen.bits", { n })}</span>

      <GenControls spec={spec} patch={patch} />

      {error && <Alert message={error} />}

      {(view.made.length > 1 || view.taken.length > 0) && (
        <div className="cols">
          <Past
            title={t("gen.previous")}
            hint={t("gen.previousHint")}
            taken={false}
            lengths={view.made}
            from={1}
            onCopy={(i) => void copyAt(false, i)}
            onClear={() => void invoke<HistoryView>("forget_generated", { taken: false }).then(setView).catch(() => {})}
          />
          <Past
            title={t("gen.taken")}
            hint={t("gen.takenHint")}
            taken
            lengths={view.taken}
            from={0}
            onCopy={(i) => void copyAt(true, i)}
            onClear={() => void invoke<HistoryView>("forget_generated", { taken: true }).then(setView).catch(() => {})}
          />
        </div>
      )}
    </div>
  );
}


/*
  The generator's settings, one block for the screen and for the modal.

  The modal is needed where a password is thought up for one particular item:
  the button in a password field used to put something default in silently, and
  there was nowhere to fit the length or the set of characters to somebody
  else's demands except a separate screen — at the cost of the form already
  typed.
*/
export function GenControls({ spec, patch }: { spec: Spec; patch: (change: Partial<Spec>) => void }) {
  return (
    <>
      <div className="field">
      <label>{t("gen.preset")}</label>
      {/* A single choice is a joined group, as the length is. The ready-made
          sets used to look like the same tags as the "what to build it from"
          switches below, though they behave the other way round: there
          everything can be on at once, here it is one of them. */}
      <div className="choice">
        <div className="cells">
          {PRESETS.map((p) => (
            <button
              key={p.key}
              type="button"
              className={matches(spec, p.spec) ? "on" : ""}
              onClick={() => patch(p.spec)}
            >
              {t(`gen.preset.${p.key}` as never)}
            </button>
          ))}
        </div>
      </div>
    </div>

    <div className="field">
      <label>{t("gen.length")}</label>
      <div className="choice">
        <div className="cells">
          {LENGTHS.map((l) => (
            <button
              key={l}
              type="button"
              className={l === spec.length ? "on" : ""}
              onClick={() => patch({ length: l })}
            >
              {l}
            </button>
          ))}
        </div>
        <input
          className="len"
          type="range"
          min={4}
          max={128}
          value={spec.length}
          onChange={(e) => patch({ length: Number(e.target.value) })}
          aria-label={t("gen.length")}
        />
        <output className="len-value mono">{spec.length}</output>
      </div>
    </div>

    <div className="field">
      <label>{t("gen.sets")}</label>
      {/* On one line: these are five switches of one property rather than five
          different settings, and in a column they read as a list of chores. */}
      <div className="setchips">
        <Set label="A–Z" hint={t("gen.upper")} on={spec.upper} onChange={(v) => patch({ upper: v })} />
        <Set label="a–z" hint={t("gen.lower")} on={spec.lower} onChange={(v) => patch({ lower: v })} />
        <Set label="0–9" hint={t("gen.digits")} on={spec.digits} onChange={(v) => patch({ digits: v })} />
        <Set label="!#$" hint={t("gen.symbols")} on={spec.symbols} onChange={(v) => patch({ symbols: v })} />
      </div>
    </div>

    {/* Restrictions are not the same as "what to build it from": they add no
        characters, they forbid. They used to stand in the same row behind a
        vertical rule, and the difference rested on that rule alone. */}
    <div className="field">
      <label>{t("gen.limits")}</label>
      <div className="setchips">
        <Set
          label="0O1lI"
          hint={t("gen.ambiguous")}
          on={spec.avoid_ambiguous}
          onChange={(v) => patch({ avoid_ambiguous: v })}
          strike
        />
        {spec.symbols && (
          <Set
            label={t("gen.inside")}
            hint={t("gen.insideHint")}
            on={spec.symbols_inside_only}
            onChange={(v) => patch({ symbols_inside_only: v })}
          />
        )}
      </div>
    </div>
    </>
  );
}

/// The list of past passwords.
function Past({
  title,
  hint,
  taken,
  lengths,
  from,
  onCopy,
  onClear,
}: {
  title: string;
  hint: string;
  taken: boolean;
  /// A length per password; from `from` on they are this list's.
  lengths: number[];
  from: number;
  onCopy: (index: number) => void;
  onClear: () => void;
}) {
  // A shown value hides itself soon, and at once when the window is left.
  const { values, keep, forget } = useEphemeral(taken);
  const rows = lengths.map((n, i) => ({ n, i })).slice(from);
  if (rows.length === 0) return null;
  const toggle = async (i: number) => {
    const k = String(i);
    if (values[k] !== undefined) return forget(k);
    try {
      keep(k, await invokeSecret("reveal_generated", { taken, index: i }));
    } catch {
      // Gone from the history meanwhile: nothing to show.
    }
  };
  return (
    <div className="field">
      <div className="between">
        <label>{title}</label>
        <button type="button" className="link" onClick={onClear}>
          {t("gen.forget")}
        </button>
      </div>
      <div className="list">
        {rows.map(({ n, i }) => (
          <Line key={i} length={n} shown={values[String(i)]} onToggle={() => void toggle(i)} onCopy={() => onCopy(i)} />
        ))}
      </div>
      <span className="hint">{hint}</span>
    </div>
  );
}

/// A row of the history.
///
/// Hidden by default: a list of what was copied is by definition a set of live
/// passwords to other people's services, and one screenshot of the generator
/// tab handed them all out at once. The window does not even have the value
/// until "show" is pressed.
function Line({ length, shown, onToggle, onCopy }: { length: number; shown?: string; onToggle: () => void; onCopy: () => void }) {
  return (
    <div className="row plain past">
      <span className="text mono">{shown ?? "•".repeat(Math.min(length, 24))}</span>
      <span className="side">
        <button type="button"
          className="btn icon-only"
          onClick={onToggle}
          title={t(shown ? "action.hide" : "action.reveal")}
          aria-label={t(shown ? "action.hide" : "action.reveal")}
        >
          <Icon name="eye" size={13} />
        </button>
        <button type="button" className="btn icon-only" onClick={onCopy} title={t("action.copy")} aria-label={t("action.copy")}>
          <Icon name="copy" size={13} />
        </button>
      </span>
    </div>
  );
}

function Set({
  label,
  hint,
  on,
  onChange,
  strike = false,
}: {
  label: string;
  hint: string;
  on: boolean;
  onChange: (v: boolean) => void;
  strike?: boolean;
}) {
  return (
    <button
      type="button"
      className={`setchip ${on ? "on" : ""} ${strike ? "strike" : ""}`}
      aria-pressed={on}
      title={hint}
      onClick={() => onChange(!on)}
    >
      <span className="mono">{label}</span>
    </button>
  );
}
