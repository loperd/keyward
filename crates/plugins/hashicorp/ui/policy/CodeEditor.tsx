/// The shared wrapper around CodeMirror: a theme built on our own variables,
/// highlighting and a minimal set of keys. The language, the completions and the
/// linting are set by the caller.
import { useEffect, useRef } from "react";
import { EditorState, Prec, type Extension } from "@codemirror/state";
import { EditorView, keymap, lineNumbers, highlightActiveLine, drawSelection, placeholder as cmPlaceholder } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { bracketMatching, syntaxHighlighting, HighlightStyle, indentOnInput, StreamLanguage, type StringStream } from "@codemirror/language";
import { closeBrackets, closeBracketsKeymap, completionKeymap, completionStatus, closeCompletion } from "@codemirror/autocomplete";
import { tags } from "@lezer/highlight";

export const highlight = HighlightStyle.define([
  { tag: tags.keyword, color: "var(--sky)", fontWeight: "600" },
  { tag: tags.propertyName, color: "var(--orange)" },
  { tag: tags.string, color: "var(--mint)" },
  { tag: tags.atom, color: "var(--amber)" },
  { tag: tags.comment, color: "var(--dim)", fontStyle: "italic" },
  { tag: tags.number, color: "var(--amber)" },
  { tag: [tags.bracket, tags.brace, tags.punctuation], color: "var(--dim)" },
  { tag: tags.invalid, color: "var(--rose)", textDecoration: "underline wavy" },
  { tag: tags.variableName, color: "var(--text)" },
]);

export const theme = EditorView.theme({
  "&": { fontSize: "12px", backgroundColor: "var(--field)", border: "1px solid var(--edge)", borderRadius: "var(--r)", color: "var(--text)" },
  "&.cm-focused": { outline: "none", borderColor: "var(--sky)", boxShadow: "var(--ring)" },
  ".cm-scroller": { fontFamily: "var(--mono)", lineHeight: "1.6", minHeight: "var(--editor-min, 220px)", maxHeight: "var(--editor-max, 46vh)" },
  ".cm-content": { padding: "8px 0", caretColor: "var(--text)" },
  ".cm-line": { padding: "0 10px" },
  ".cm-gutters": { backgroundColor: "transparent", color: "var(--dim)", border: "none", borderRight: "1px solid var(--edge-soft)" },
  ".cm-lineNumbers .cm-gutterElement": { padding: "0 6px 0 10px", minWidth: "32px" },
  ".cm-activeLine": { backgroundColor: "color-mix(in srgb, var(--sky) 7%, transparent)" },
  ".cm-activeLineGutter": { backgroundColor: "transparent", color: "var(--text)" },
  ".cm-selectionBackground, &.cm-focused .cm-selectionBackground": { backgroundColor: "color-mix(in srgb, var(--sky) 28%, transparent) !important" },
  ".cm-cursor": { borderLeftColor: "var(--text)" },
  ".cm-matchingBracket": { backgroundColor: "color-mix(in srgb, var(--mint) 22%, transparent)", outline: "none" },
  ".cm-tooltip": { backgroundColor: "var(--surface)", border: "1px solid var(--edge)", borderRadius: "var(--r)", color: "var(--text)", fontFamily: "var(--mono)", fontSize: "11.5px", boxShadow: "0 8px 24px rgba(0,0,0,.28)" },
  ".cm-tooltip.cm-tooltip-autocomplete > ul": { fontFamily: "var(--mono)" },
  ".cm-tooltip.cm-tooltip-autocomplete > ul > li": { padding: "3px 8px" },
  ".cm-tooltip.cm-tooltip-autocomplete > ul > li[aria-selected]": { backgroundColor: "color-mix(in srgb, var(--sky) 22%, transparent)", color: "var(--text)" },
  ".cm-completionLabel": { color: "var(--text)" },
  ".cm-completionMatchedText": { color: "var(--sky)", textDecoration: "none", fontWeight: "600" },
  ".cm-completionDetail": { color: "var(--dim)", fontStyle: "normal", marginLeft: "8px" },
  ".cm-completionIcon": { display: "none" },
  ".cm-tooltip-lint": { padding: "4px 0" },
  ".cm-diagnostic": { padding: "3px 8px", borderLeft: "3px solid" },
  ".cm-diagnostic-error": { borderLeftColor: "var(--rose)" },
  ".cm-diagnostic-warning": { borderLeftColor: "var(--amber)" },
  ".cm-diagnostic-info": { borderLeftColor: "var(--sky)" },
  ".cm-lintRange-error": { backgroundImage: "none", textDecoration: "underline wavy var(--rose)" },
  ".cm-lintRange-warning": { backgroundImage: "none", textDecoration: "underline wavy var(--amber)" },
  ".cm-lintRange-info": { backgroundImage: "none", textDecoration: "underline dotted var(--sky)" },
  ".cm-gutter-lint .cm-gutterElement": { padding: "0 2px 0 4px" },
  ".cm-lint-marker-error": { content: "none", background: "var(--rose)", borderRadius: "50%", width: "7px", height: "7px", margin: "auto" },
  ".cm-lint-marker-warning": { content: "none", background: "var(--amber)", borderRadius: "50%", width: "7px", height: "7px", margin: "auto" },
  ".cm-lint-marker-info": { content: "none", background: "var(--sky)", borderRadius: "50%", width: "7px", height: "7px", margin: "auto" },
  ".cm-placeholder": { color: "var(--dim)", fontStyle: "italic" },
});

/// Escape while a completion is open closes the completion rather than the
/// modal around it.
export const escapeClosesCompletion = Prec.highest(
  EditorView.domEventHandlers({
    keydown(e, v) {
      if (e.key === "Escape" && completionStatus(v.state)) {
        closeCompletion(v);
        // The one Escape stack leaves the dialogue alone after this.
        e.preventDefault();
        e.stopPropagation();
        return true;
      }
      return false;
    },
  }),
);

export const baseExtensions: Extension[] = [
  lineNumbers(),
  EditorView.lineWrapping,
  history(),
  drawSelection(),
  highlightActiveLine(),
  bracketMatching(),
  closeBrackets(),
  indentOnInput(),
  syntaxHighlighting(highlight),
  theme,
  EditorState.tabSize.of(2),
  escapeClosesCompletion,
  keymap.of([...closeBracketsKeymap, ...completionKeymap, ...historyKeymap, indentWithTab, ...defaultKeymap]),
];

/// `.env`: a variable's name, an equals sign, a value. Highlighting only —
/// `parseEnv` does the parsing.
export const envLanguage = StreamLanguage.define<{ sol: boolean }>({
  name: "dotenv",
  startState: () => ({ sol: true }),
  token(stream: StringStream) {
    if (stream.sol()) {
      if (stream.match(/^\s*#.*/)) return "comment";
      if (stream.match(/^\s*(export\s+)?[A-Za-z_][A-Za-z0-9_.-]*(?=\s*[=:])/)) return "propertyName";
      if (stream.match(/^\s*\S.*/)) return "invalid";
    }
    if (stream.match(/^\s*[=:]\s*/)) return "punctuation";
    if (stream.match(/^"(?:[^"\\]|\\.)*"/) || stream.match(/^'[^']*'/)) return "string";
    if (stream.match(/^.+/)) return "string";
    stream.next();
    return null;
  },
  languageData: { commentTokens: { line: "#" } },
});

/// Controlled from outside by its initial value alone: the text lives in the
/// editor and leaves through `onChange`. It is not recreated when `extensions`
/// change — those are set once.
export function CodeEditor({
  initial,
  onChange,
  extensions,
  placeholder,
  autoFocus = false,
  minHeight,
  maxHeight,
  viewRef,
}: {
  initial: string;
  onChange: (text: string) => void;
  extensions?: Extension[];
  placeholder?: string;
  autoFocus?: boolean;
  minHeight?: string;
  maxHeight?: string;
  viewRef?: (v: EditorView | null) => void;
}) {
  const host = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!host.current) return;
    const v = new EditorView({
      state: EditorState.create({
        doc: initial,
        extensions: [
          ...baseExtensions,
          ...(extensions ?? []),
          ...(placeholder ? [cmPlaceholder(placeholder)] : []),
          EditorView.updateListener.of((u) => {
            if (u.docChanged) onChange(u.state.doc.toString());
          }),
        ],
      }),
      parent: host.current,
    });
    viewRef?.(v);
    if (autoFocus) v.focus();
    return () => {
      v.destroy();
      viewRef?.(null);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const style = {
    ...(minHeight ? { ["--editor-min" as string]: minHeight } : {}),
    ...(maxHeight ? { ["--editor-max" as string]: maxHeight } : {}),
  } as React.CSSProperties;

  return <div className="studio" ref={host} style={style} />;
}
