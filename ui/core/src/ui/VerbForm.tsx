// A preview's controls: a line of text, or a row of choices. Each writes the
// line's argument (the verb decides how), so the sheet, the line and the URL
// are one state and a picture of the line is a picture of the sheet. A row
// is a label in the field column and one 32px control beside it.
import { useEffect, useRef, useState } from "react";
import { text, type Text } from "../i18n";
import type { FormGroup, Input } from "../verbs/spec";
import { Icon } from "./Icons";
import { Tile, useCore } from "./marks";
import "./sheet.css";

const say = (x: Text) => text(x);

function Label({ inp }: { inp: Input }) {
  return (
    <span className="fl">
      {inp.lead && <Tile lead={inp.lead} />}
      <span>{say(inp.label)}</span>
    </span>
  );
}

function TextRow({ inp, setArg, onEnter, first }: { inp: Extract<Input, { text: string }>; setArg: (a: string) => void; onEnter: () => void; first: boolean }) {
  // What is typed stays as typed while the field has focus: the argument
  // is written back in its own form ("a, b" → "a b"), and the caret must
  // not jump under the fingers.
  const [v, setV] = useState(inp.text);
  const focused = useRef(false);
  const el = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (!focused.current) setV(inp.text);
  }, [inp.text]);
  // The first empty field takes the keys when the sheet opens, once.
  const opened = useRef(false);
  useEffect(() => {
    if (opened.current) return;
    opened.current = true;
    if (first && !inp.text) el.current?.focus();
  }, [first, inp.text]);
  return (
    <div className="frow">
      <Label inp={inp} />
      <label className="fin">
        <input
          ref={el}
          className={inp.mono ? "mono" : undefined}
          value={v}
          spellCheck={false}
          autoComplete="off"
          placeholder={inp.placeholder ? say(inp.placeholder) : undefined}
          aria-label={say(inp.label)}
          onFocus={() => (focused.current = true)}
          onBlur={() => {
            focused.current = false;
            setV(inp.text);
          }}
          onChange={(e) => {
            setV(e.target.value);
            setArg(inp.with(e.target.value));
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              onEnter();
            } else if (e.key === "Escape") {
              e.preventDefault();
              e.currentTarget.blur();
            }
          }}
        />
      </label>
    </div>
  );
}

function ChoiceRow({ inp, setArg }: { inp: Extract<Input, { choices: unknown }>; setArg: (a: string) => void }) {
  return (
    <div className={`frow${inp.toggle ? " frow-t" : ""}`}>
      <Label inp={inp} />
      <div className="fseg" role="radiogroup" aria-label={say(inp.label)}>
        {inp.choices.map((c, i) => (
          <button
            key={i}
            type="button"
            role="radio"
            aria-checked={c.on}
            className={c.on ? "on" : undefined}
            disabled={!!c.off && !c.on}
            {...(c.off && !c.on ? { "data-tip": say(c.off) } : {})}
            onClick={() => !c.on && setArg(c.arg)}
          >
            {say(c.label)}
          </button>
        ))}
      </div>
      {inp.toggle && (
        <button
          type="button"
          className={`btn ico ftog tip-l${inp.toggle.on ? " on" : ""}`}
          aria-pressed={inp.toggle.on}
          aria-label={say(inp.toggle.off ?? inp.toggle.label)}
          data-tip={say(inp.toggle.off ?? inp.toggle.label)}
          disabled={!!inp.toggle.off}
          onClick={() => setArg(inp.toggle!.arg)}
        >
          <Icon name="eye" />
          {inp.toggle.on && <i className="slash" aria-hidden />}
        </button>
      )}
    </div>
  );
}

export function VerbForm({ form, onEnter }: { form: FormGroup[]; onEnter: () => void }) {
  const { store } = useCore();
  // A control's change replaces the line in place: choosing is not a step
  // of history, as walking a column is not.
  const setArg = (arg: string) => {
    const s = store.get().state;
    store.commitState({ ...s, arg }, { replace: true });
  };
  let firstText = true;
  return (
    <>
      {form.map((g, gi) => (
        <section key={gi} className={gi === 0 && !g.title ? "form form-top" : "sec form"}>
          {g.title && (
            <div className="sec-h">
              <h2 className="h2">{say(g.title)}</h2>
            </div>
          )}
          {g.inputs.map((inp) => {
            if ("text" in inp) {
              const first = firstText;
              firstText = false;
              return <TextRow key={inp.id} inp={inp} setArg={setArg} onEnter={onEnter} first={first} />;
            }
            return <ChoiceRow key={inp.id} inp={inp} setArg={setArg} />;
          })}
        </section>
      ))}
    </>
  );
}
