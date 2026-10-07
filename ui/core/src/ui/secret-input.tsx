// A field for a secret a person types (a master password, a PIN, a code, a
// new password). It is uncontrolled: the value lives in the input's own
// `.value` only — never in React state, never in a `value` attribute of the
// DOM (a controlled input mirrors what is typed there) — and is read once,
// by `take()`, which empties the field in the same step. The field is
// emptied when it goes away as well. Whether it holds anything is all the
// form is told, for its submit button.
import { useEffect, useImperativeHandle, useRef, type Ref } from "react";

export type SecretInputHandle = {
  /// The typed value, and the field emptied at once.
  take(): string;
  /// The typed value, the field left as it is: for a flow of several steps
  /// that sends it at each (two-step login's setup) and `take`s it at the
  /// last. Never kept by the caller.
  read(): string;
  /// Empties the field without reading it.
  clear(): void;
  /// Puts a value in (a generated password): into the field's `.value`
  /// only, never through React.
  set(value: string): void;
  focus(): void;
};

export type SecretInputProps = {
  ref?: Ref<SecretInputHandle>;
  /// Told whether the field holds anything, on every keystroke and on `take`.
  onFilled?: (filled: boolean) => void;
  /// Shown as text (an eye pressed, a one-time code) rather than dots.
  shown?: boolean;
  /// Several lines (a note, a private key): a textarea, masked by the
  /// caller's class while not `shown`.
  multiline?: boolean;
  rows?: number;
  autoComplete?: string;
  inputMode?: "numeric" | "text";
  autoFocus?: boolean;
  disabled?: boolean;
  className?: string;
  "aria-label"?: string;
  placeholder?: string;
};

export function SecretInput({ ref, onFilled, shown = false, multiline = false, rows, autoComplete = "off", inputMode, autoFocus, disabled, className, placeholder, ...aria }: SecretInputProps) {
  const el = useRef<HTMLInputElement & HTMLTextAreaElement>(null);
  const filled = useRef(onFilled);
  filled.current = onFilled;
  useImperativeHandle(
    ref,
    () => ({
      take() {
        const input = el.current;
        if (!input) throw new Error("a secret field was read after it was gone");
        const v = input.value;
        input.value = "";
        filled.current?.(false);
        return v;
      },
      read() {
        const input = el.current;
        if (!input) throw new Error("a secret field was read after it was gone");
        return input.value;
      },
      clear() {
        if (el.current) el.current.value = "";
        filled.current?.(false);
      },
      set(value: string) {
        const input = el.current;
        if (!input) throw new Error("a secret field was written after it was gone");
        input.value = value;
        filled.current?.(value !== "");
      },
      focus() {
        el.current?.focus();
      },
    }),
    [],
  );
  useEffect(() => {
    const input = el.current;
    return () => {
      if (input) input.value = "";
    };
  }, []);
  const common = {
    ref: el,
    className,
    onInput: (e: { currentTarget: { value: string } }) => filled.current?.(e.currentTarget.value !== ""),
    autoComplete,
    inputMode,
    spellCheck: false,
    autoCapitalize: "off",
    autoCorrect: "off",
    autoFocus,
    disabled,
    placeholder,
    "aria-label": aria["aria-label"],
  };
  return multiline ? <textarea {...common} rows={rows} /> : <input {...common} type={shown ? "text" : "password"} />;
}
