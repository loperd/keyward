import { useState } from "react";
import { Icon } from "./ui";
import { GeneratorModal } from "./screens/GeneratorModal";
import { t } from "./i18n";

/// The password field, one for the whole application.
///
/// Every password field has an eye: a hidden value cannot be checked, and a
/// typo in a master password or a card's code costs dearly. The generate button
/// belongs only to an empty field and only where a password is being thought up
/// (an item's password, a hidden custom field): on a filled-in field it would
/// write over what was typed, and on a master password it has no business at
/// all.
export function PasswordInput({
  value,
  onChange,
  generate = false,
  placeholder,
  autoFocus,
  ariaLabel,
  onKeyDown,
  inputMode,
}: {
  value: string;
  onChange: (v: string) => void;
  generate?: boolean;
  placeholder?: string;
  autoFocus?: boolean;
  ariaLabel?: string;
  onKeyDown?: (e: React.KeyboardEvent<HTMLInputElement>) => void;
  /// `numeric` is for a PIN: the same hiding and the same eye, but a numeric
  /// keyboard.
  inputMode?: "numeric" | "text";
}) {
  const [shown, setShown] = useState(false);
  const [gen, setGen] = useState(false);
  const canGenerate = generate && value === "";
  return (
    <div className={`with-inner pw ${canGenerate ? "two" : ""}`}>
      <input
        type={shown ? "text" : "password"}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        autoFocus={autoFocus}
        aria-label={ariaLabel ?? placeholder}
        spellCheck={false}
        autoComplete="off"
        inputMode={inputMode}
        onKeyDown={onKeyDown}
      />
      <span className="inners">
        {canGenerate && (
          <button type="button" className="inner" onClick={() => setGen(true)} title={t("nav.generator")} aria-label={t("nav.generator")}>
            <Icon name="sync" size={12} />
          </button>
        )}
        <button
          type="button"
          className="inner"
          onClick={() => setShown((s) => !s)}
          title={shown ? t("detail.hide") : t("detail.reveal")}
          aria-label={shown ? t("detail.hide") : t("detail.reveal")}
        >
          <Icon name={shown ? "eye-off" : "eye"} size={12} />
        </button>
      </span>
      {gen && (
        <GeneratorModal
          onClose={() => setGen(false)}
          onUse={(v) => {
            onChange(v);
            setGen(false);
          }}
        />
      )}
    </div>
  );
}
