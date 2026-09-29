/// The password generator over an item's form.
///
/// The same block of settings as on the screen of its own, and the same daemon
/// that assembles the password: the randomness comes from the system, not from
/// the webview. There is one difference — the result is not copied to the
/// clipboard but returned to the field the generator was called from.
import { useCallback, useEffect, useState } from "react";
import { Alert, Icon, Modal } from "../ui";
import { t } from "../i18n";
import { DEFAULT_SPEC, GenControls, bits, strength, type Spec } from "./Generator";
import { invokeSecret } from "../seal";

export function GeneratorModal({
  onClose,
  onUse,
}: {
  onClose: () => void;
  /// The finished password goes to the field the generator was opened from.
  onUse: (password: string) => void;
}) {
  const [spec, setSpec] = useState<Spec>(DEFAULT_SPEC);
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);

  const make = useCallback(async (next: Spec) => {
    try {
      setValue(await invokeSecret("generate_password", { spec: next }));
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    void make(DEFAULT_SPEC);
  }, [make]);

  const patch = (change: Partial<Spec>) => {
    const next = { ...spec, ...change };
    setSpec(next);
    void make(next);
  };

  const n = bits(spec);
  const level = strength(n);

  return (
    <Modal
      wide
      title={t("nav.generator")}
      onClose={onClose}
      onSubmit={() => value && onUse(value)}
      footer={
        <>
          <button
            type="button"
            className="btn primary"
            disabled={!value}
            onClick={() => value && onUse(value)}
          >
            {t("gen.use")}
          </button>
          <button type="button" className="btn" onClick={onClose}>
            {t("action.cancel")}
          </button>
        </>
      }
    >
      <div className="readout">
        <output className="mono">{value || "…"}</output>
        <span className="acts">
          <button
            type="button"
            className="btn icon-only"
            onClick={() => void make(spec)}
            title={t("gen.again")}
            aria-label={t("gen.again")}
          >
            <Icon name="sync" size={14} />
          </button>
        </span>
      </div>

      <div className={`meter ${level}`}>
        <span style={{ width: `${Math.min(100, (n / 128) * 100)}%` }} />
      </div>
      <span className="hint">
        {t(`gen.strength.${level}`)} · {t("gen.bits", { n })}
      </span>

      <GenControls spec={spec} patch={patch} />

      {error && <Alert message={error} />}
    </Modal>
  );
}
