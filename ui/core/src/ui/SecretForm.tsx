// A preview's secret fields: what the line must never carry (a master
// password, a PIN), typed into the sheet. Each field is a `SecretInput` —
// its value lives in the input only and is read once, at ↵, by `take`, which
// empties every field in the same step. The form tells the preview only
// whether every field holds something.
import { useEffect, useImperativeHandle, useRef, useState, type Ref } from "react";
import { t, text } from "../i18n";
import { type SecretAsk, SecretAskKind } from "../verbs/spec";
import { SecretInput, type SecretInputHandle } from "./secret-input";
import { IconButton } from "./marks";
import "./sheet.css";

export type SecretFormHandle = {
  /// What was typed, by the fields' ids; every field emptied at once.
  take(): Record<string, string>;
};

const AUTOCOMPLETE: Record<SecretAskKind, string> = {
  [SecretAskKind.Password]: "current-password",
  [SecretAskKind.NewPassword]: "new-password",
  [SecretAskKind.Pin]: "off",
};

function Field({ ask, handle, onFilled, onEnter, first }: { ask: SecretAsk; handle: Ref<SecretInputHandle>; onFilled: (f: boolean) => void; onEnter: () => void; first: boolean }) {
  const [shown, setShown] = useState(false);
  const label = text(ask.label);
  return (
    <div className="frow frow-t">
      <span className="fl">
        <span>{label}</span>
      </span>
      <label
        className="fin"
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            e.stopPropagation();
            onEnter();
          }
        }}
      >
        <SecretInput ref={handle} onFilled={onFilled} shown={shown} autoComplete={AUTOCOMPLETE[ask.kind]} {...(ask.kind === SecretAskKind.Pin ? { inputMode: "numeric" as const } : {})} autoFocus={first} aria-label={label} />
      </label>
      <IconButton icon="eye" className={shown ? "on tip-l" : "tip-l"} tip={shown ? t("gate.hidePassword") : t("gate.showPassword")} onClick={() => setShown(!shown)} />
    </div>
  );
}

export function SecretForm({ ref, asks, onFilled, onEnter }: { ref: Ref<SecretFormHandle>; asks: SecretAsk[]; onFilled: (all: boolean) => void; onEnter: () => void }) {
  const fields = useRef(new Map<string, SecretInputHandle>());
  const [filled, setFilled] = useState<ReadonlySet<string>>(new Set());
  const all = asks.every((a) => filled.has(a.id));
  const told = useRef(onFilled);
  told.current = onFilled;
  useEffect(() => told.current(all), [all]);
  useImperativeHandle(
    ref,
    () => ({
      take() {
        const out: Record<string, string> = {};
        // Every field is read, and so emptied, even past one that is gone.
        let missing: string | null = null;
        for (const a of asks) {
          const f = fields.current.get(a.id);
          if (!f) missing = a.id;
          else out[a.id] = f.take();
        }
        if (missing) throw new Error(`the secret field "${missing}" was read after it was gone`);
        return out;
      },
    }),
    [asks],
  );
  return (
    <section className="form form-top">
      {asks.map((a, i) => (
        <Field
          key={a.id}
          ask={a}
          first={i === 0}
          handle={(h) => {
            if (h) fields.current.set(a.id, h);
            else fields.current.delete(a.id);
          }}
          onFilled={(f) =>
            setFilled((s) => {
              if (f === s.has(a.id)) return s;
              const next = new Set(s);
              if (f) next.add(a.id);
              else next.delete(a.id);
              return next;
            })
          }
          onEnter={onEnter}
        />
      ))}
    </section>
  );
}
