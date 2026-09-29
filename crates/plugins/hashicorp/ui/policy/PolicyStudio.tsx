/// The editor for a Vault policy: highlighting, completions, linting,
/// formatting and the insertion of ready-made blocks. One modal for a new policy
/// and for editing one alike.
///
/// There is deliberately no builder of "an engine gives these rights": it
/// substituted text that had been typed by hand. In its place is a menu that
/// inserts at the cursor.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { EditorView } from "@codemirror/view";
import { undo, redo, undoDepth, redoDepth } from "@codemirror/commands";
import { autocompletion } from "@codemirror/autocomplete";
import { linter, lintGutter, type Diagnostic } from "@codemirror/lint";
import { Alert, Icon, Modal, Picker } from "@keyward/ui";
import { CodeEditor } from "./CodeEditor";
import { t } from "@keyward/i18n";
import type { Key } from "@keyward/i18n";
import { call } from "@keyward/plugins/call";
import type { Mount, Policy } from "../types";
import { CAPABILITIES, formatPolicy, hclLanguage, lintPolicy, makeCompletion, templates, type LintKey, type Parsed } from "./hcl";

const lintMsg = (key: LintKey, vars?: Record<string, string | number>) => t(`lint.${key}` as Key, vars);

/// A point in the history: what was in the editor and why the point
/// appeared.
type Snap = { id: number; at: number; label: string; text: string; added: number; removed: number };

/// How many lines were added and lost between two texts — roughly, by sets of
/// lines. For a caption in the history that is accurate enough.
function lineDelta(before: string, after: string): { added: number; removed: number } {
  const count = (s: string) => {
    const m = new Map<string, number>();
    for (const l of s.split("\n")) m.set(l, (m.get(l) ?? 0) + 1);
    return m;
  };
  const a = count(before);
  const b = count(after);
  let added = 0;
  let removed = 0;
  for (const [l, n] of b) added += Math.max(0, n - (a.get(l) ?? 0));
  for (const [l, n] of a) removed += Math.max(0, n - (b.get(l) ?? 0));
  return { added, removed };
}

const HISTORY_LIMIT = 60;
const TYPING_PAUSE = 1200;

/// A capability's colour: reading calm, writing noticeable, deletion and sudo
/// alarming.
export function capTone(c: string): string {
  switch (c) {
    case "read":
    case "list":
      return "cap read";
    case "create":
    case "update":
    case "patch":
      return "cap write";
    case "delete":
      return "cap delete";
    case "sudo":
      return "cap sudo";
    case "deny":
      return "cap deny";
    default:
      return "cap unknown";
  }
}

export function PolicyStudio({
  policy,
  onClose,
  onSaved,
}: {
  /// An existing policy means an edit; its absence, a new one.
  policy: Policy | null;
  onClose: () => void;
  onSaved: (p: Policy) => void;
}) {
  const isNew = policy === null;
  const [name, setName] = useState(policy?.name ?? "");
  const [text, setText] = useState(policy?.rules ?? "");
  const [mounts, setMounts] = useState<Mount[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const view = useRef<EditorView | null>(null);
  const mountsRef = useRef<Mount[]>([]);
  mountsRef.current = mounts;

  // A history of edits: insertions, formatting and pauses in typing. Ctrl+Z
  // works without it, but going back "to what was there before the block was
  // inserted" is easier when that point is visible and named.
  const [history, setHistory] = useState<Snap[]>(() => [
    { id: 1, at: Date.now(), label: t("policy.hist.initial"), text: policy?.rules ?? "", added: 0, removed: 0 },
  ]);
  const [applied, setApplied] = useState(1);
  const seq = useRef(1);
  const lastSnap = useRef(policy?.rules ?? "");
  const typingTimer = useRef<number | null>(null);
  const [depths, setDepths] = useState({ undo: 0, redo: 0 });

  const snapshot = useCallback((label: string, text: string) => {
    if (text === lastSnap.current) return;
    const delta = lineDelta(lastSnap.current, text);
    lastSnap.current = text;
    seq.current += 1;
    const id = seq.current;
    setHistory((h) => [...h, { id, at: Date.now(), label, text, ...delta }].slice(-HISTORY_LIMIT));
    setApplied(id);
  }, []);

  const onText = useCallback(
    (next: string) => {
      setText(next);
      const v = view.current;
      if (v) setDepths({ undo: undoDepth(v.state), redo: redoDepth(v.state) });
      if (typingTimer.current !== null) window.clearTimeout(typingTimer.current);
      typingTimer.current = window.setTimeout(() => snapshot(t("policy.hist.typing"), next), TYPING_PAUSE);
    },
    [snapshot],
  );

  useEffect(() => () => {
    if (typingTimer.current !== null) window.clearTimeout(typingTimer.current);
  }, []);

  /// Replace the text whole in one operation, which is also one undo under
  /// Ctrl+Z.
  const replaceAll = (next: string) => {
    const v = view.current;
    if (!v) return;
    v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: next } });
    v.focus();
  };

  const restore = (s: Snap) => {
    if (typingTimer.current !== null) window.clearTimeout(typingTimer.current);
    replaceAll(s.text);
    snapshot(t("policy.hist.restore", { when: new Date(s.at).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }) }), s.text);
    setApplied(s.id);
  };

  useEffect(() => {
    call<Mount[]>("hashicorp", "mounts")
      .then(setMounts)
      .catch(() => setMounts([]));
  }, []);

  // The parse is computed on every change: the summary and the footer live off
  // it, while the editor's linter runs on a call of its own, with a delay.
  const { parsed, diagnostics } = useMemo(() => lintPolicy(text, mounts, lintMsg), [text, mounts]);
  const errors = diagnostics.filter((d) => d.severity === "error").length;
  const warnings = diagnostics.filter((d) => d.severity === "warning").length;

  const lintSource = useCallback((v: EditorView): Diagnostic[] => lintPolicy(v.state.doc.toString(), mountsRef.current, lintMsg).diagnostics, []);

  const extensions = useMemo(
    () => [
      lintGutter(),
      hclLanguage,
      autocompletion({ override: [makeCompletion(() => mountsRef.current)], activateOnTyping: true, icons: false }),
      linter(lintSource, { delay: 250 }),
    ],
    [lintSource],
  );

  /// An insertion at the cursor with a blank line from its neighbours. It
  /// replaces nothing.
  const insert = (body: string, label: string) => {
    const v = view.current;
    if (!v) return;
    const { from, to } = v.state.selection.main;
    const doc = v.state.doc;
    const lineStart = doc.lineAt(from).from;
    const before = doc.sliceString(0, lineStart);
    const after = doc.sliceString(to);
    let chunk = body.replace(/\s+$/, "") + "\n";
    if (before.trim() !== "" && !before.endsWith("\n\n")) chunk = (before.endsWith("\n") ? "\n" : "\n\n") + chunk;
    if (after.trim() !== "" && !after.startsWith("\n")) chunk += "\n";
    const at = before.trim() === "" ? 0 : lineStart;
    if (typingTimer.current !== null) window.clearTimeout(typingTimer.current);
    // What was there before the insertion is a point of its own: that is what
    // anybody will want to come back to.
    snapshot(t("policy.hist.typing"), v.state.doc.toString());
    v.dispatch({ changes: { from: at, to, insert: chunk }, selection: { anchor: at + chunk.length } });
    v.focus();
    snapshot(t("policy.hist.insert", { t: label }), v.state.doc.toString());
  };

  const format = () => {
    const v = view.current;
    if (!v) return;
    const out = formatPolicy(parsed, v.state.doc.toString());
    if (out === null || out === v.state.doc.toString()) return;
    if (typingTimer.current !== null) window.clearTimeout(typingTimer.current);
    snapshot(t("policy.hist.typing"), v.state.doc.toString());
    replaceAll(out);
    snapshot(t("policy.hist.format"), out);
  };

  const cleanName = name.trim();
  const nameOk = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(cleanName) && cleanName.length <= 128;
  const why = isNew && !nameOk ? t("policy.studio.needName") : text.trim() === "" ? t("policy.studio.needBody") : errors > 0 ? t("policy.studio.hasErrors", { n: errors }) : null;
  const unchanged = !isNew && text === policy.rules;

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await call<string[]>("hashicorp", "put_policy", { name: cleanName, rules: text });
      onSaved({ name: cleanName, rules: text });
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const tpls = useMemo(() => templates(mounts, (k, vars) => t(k as Key, vars)), [mounts]);

  return (
    <Modal
      title={isNew ? t("policy.newTitle") : t("policy.editTitle", { name: policy.name })}
      onClose={onClose}
      wide
      footer={
        <>
          <span className="foot-why hint">
            {why ?? (warnings > 0 ? t("policy.studio.warnings", { n: warnings }) : t("policy.studio.ok", { n: parsed.blocks.length }))}
          </span>
          <button type="button" className="btn" onClick={onClose}>
            {t("action.cancel")}
          </button>
          <button type="button" className="btn primary" disabled={busy || why !== null || unchanged} onClick={() => void save()}>
            {busy ? t("action.saving") : t("action.save")}
          </button>
        </>
      }
    >
      {isNew && (
        <div className="field">
          <label>{t("policy.name")}</label>
          <input
            type="text"
            className="mono"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="service-name-ro"
            autoFocus
            spellCheck={false}
          />
          <span className="hint">{t("policy.nameHint")}</span>
        </div>
      )}

      <div className="studio-bar">
        <Picker value={null} placeholder={t("policy.studio.insert")} options={tpls.map((x) => ({ id: x.id, label: x.label, hint: x.hint }))} onChange={(id) => {
          const x = tpls.find((y) => y.id === id);
          if (x) insert(x.body, x.label);
        }} />
        <button type="button" className="btn" disabled={errors > 0 || text.trim() === ""} title={t("policy.studio.formatHint")} onClick={format}>
          <Icon name="check" size={13} />
          {t("policy.studio.format")}
        </button>
        <span className="studio-undo">
          <button
            type="button"
            className="btn icon-only"
            disabled={depths.undo === 0}
            title={t("policy.studio.undo")}
            aria-label={t("policy.studio.undo")}
            onClick={() => {
              const v = view.current;
              if (v) {
                undo(v);
                v.focus();
              }
            }}
          >
            <Icon name="undo" size={13} />
          </button>
          <button
            type="button"
            className="btn icon-only"
            disabled={depths.redo === 0}
            title={t("policy.studio.redo")}
            aria-label={t("policy.studio.redo")}
            onClick={() => {
              const v = view.current;
              if (v) {
                redo(v);
                v.focus();
              }
            }}
          >
            <span className="mirror">
              <Icon name="undo" size={13} />
            </span>
          </button>
        </span>
      </div>

      <CodeEditor
        initial={policy?.rules ?? ""}
        onChange={onText}
        extensions={extensions}
        placeholder={t("policy.studio.placeholder")}
        autoFocus={!isNew}
        viewRef={(v) => {
          view.current = v;
        }}
      />

      <StudioSummary parsed={parsed} />

      {history.length > 1 && (
        <details className="studio-help studio-history">
          <summary>{t("policy.studio.history", { n: history.length })}</summary>
          <div className="hist">
            {[...history].reverse().map((s) => {
              const current = s.id === applied && s.text === text;
              return (
                <button
                  type="button"
                  key={s.id}
                  className={current ? "hist-row on" : "hist-row"}
                  disabled={current}
                  title={t("policy.hist.restoreHint")}
                  onClick={() => restore(s)}
                >
                  <span className="hist-when mono">{new Date(s.at).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</span>
                  <span className="hist-label">{s.label}</span>
                  <span className="hist-delta mono">
                    {s.added > 0 && <span className="plus">+{s.added}</span>}
                    {s.removed > 0 && <span className="minus">−{s.removed}</span>}
                  </span>
                </button>
              );
            })}
          </div>
        </details>
      )}

      <details className="studio-help">
        <summary>{t("policy.studio.helpTitle")}</summary>
        <ul>
          <li>{t("policy.studio.help1")}</li>
          <li>{t("policy.studio.help2")}</li>
          <li>{t("policy.studio.help3")}</li>
        </ul>
        <div className="cap-legend">
          {CAPABILITIES.map((c) => (
            <span key={c} className={capTone(c)}>
              {c}
            </span>
          ))}
        </div>
      </details>

      {error && <Alert message={error} />}
    </Modal>
  );
}

/// What a policy grants, block by block: the path and the capabilities as
/// coloured tags. It reads faster than HCL and shows sudo and deny at once.
function StudioSummary({ parsed }: { parsed: Parsed }) {
  if (parsed.blocks.length === 0) return null;
  return (
    <div className="studio-summary">
      {parsed.blocks.map((b, i) => {
        const caps = b.attrs.find((a) => a.name === "capabilities");
        const items = caps && caps.value.kind === "list" ? caps.value.items.map((x) => x.text) : [];
        const extra = b.attrs.filter((a) => a.name !== "capabilities").map((a) => a.name);
        return (
          <div className="studio-row" key={`${b.path}-${i}`}>
            <span className="mono path">{b.path}</span>
            <span className="caps">
              {items.length === 0 && <span className="cap unknown">—</span>}
              {items.map((c) => (
                <span key={c} className={capTone(c)}>
                  {c}
                </span>
              ))}
              {extra.map((a) => (
                <span key={a} className="cap attr">
                  {a}
                </span>
              ))}
            </span>
          </div>
        );
      })}
    </div>
  );
}
