import { useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { createPortal, flushSync } from "react-dom";
import { invoke } from "@tauri-apps/api/core";
import { t, tError } from "./i18n";

/* ── The icons ──────────────────────────────────────────────────────────
   One set, one 16x16 grid, one stroke width. A mismatch between icons reads
   as sloppiness faster than any other detail. */

type IconProps = { size?: number };
const stroke = { fill: "none", stroke: "currentColor", strokeWidth: 1.5, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };

export function Icon({ name, size = 16 }: IconProps & { name: string }) {
  const paths: Record<string, ReactNode> = {
    shield: <><path d="M8 1.7 13.3 3.7v4.1c0 3.1-2.1 5.7-5.3 6.9C4.8 13.5 2.7 10.9 2.7 7.8V3.7L8 1.7Z" {...stroke} /><circle cx="8" cy="7" r="1.6" {...stroke} /><path d="M8 8.6v2.6" {...stroke} /></>,
    search: <><circle cx="7.2" cy="7.2" r="4.5" {...stroke} /><path d="M10.6 10.6 14 14" {...stroke} /></>,
    login: <><circle cx="8" cy="5.6" r="2.6" {...stroke} /><path d="M3 13.4c0-2.4 2.2-3.8 5-3.8s5 1.4 5 3.8" {...stroke} /></>,
    card: <><rect x="2" y="3.8" width="12" height="8.4" rx="1.6" {...stroke} /><path d="M2 6.8h12" {...stroke} /></>,
    identity: <><rect x="2.2" y="3" width="11.6" height="10" rx="1.6" {...stroke} /><circle cx="6.4" cy="7" r="1.5" {...stroke} /><path d="M4.2 11c.4-1.1 1.2-1.7 2.2-1.7s1.8.6 2.2 1.7M10.4 6.6h2.2M10.4 9.2h2.2" {...stroke} /></>,
    note: <><path d="M3.4 2.6h9.2v10.8H3.4z" {...stroke} /><path d="M5.6 5.6h4.8M5.6 8h4.8M5.6 10.4h3" {...stroke} /></>,
    ssh_key: <><circle cx="5.4" cy="8" r="2.6" {...stroke} /><path d="M8 8h6M12 8v2.2M10.2 8v1.6" {...stroke} /></>,
    route: <><circle cx="8" cy="6.4" r="2.2" {...stroke} /><path d="M8 8.6v3.4M2.4 12h11.2" {...stroke} /></>,
    vault: <><rect x="2.2" y="2.6" width="11.6" height="10.8" rx="1.8" {...stroke} /><circle cx="8" cy="8" r="2.6" {...stroke} /><path d="M8 5.4V3.6M8 12.4v-1.8" {...stroke} /></>,
    // A gear, not a sun: eight teeth round a hub. The outline is Lucide's
    // (ISC), drawn on 24 and scaled onto our 16 with the stroke kept at 1.5.
    settings: <g transform="scale(0.6667)"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" {...stroke} strokeWidth={2.25} /><circle cx="12" cy="12" r="3" {...stroke} strokeWidth={2.25} /></g>,
    lock: <><rect x="3.4" y="7" width="9.2" height="6.4" rx="1.4" {...stroke} /><path d="M5.6 7V5.2a2.4 2.4 0 0 1 4.8 0V7" {...stroke} /></>,
    sync: <><path d="M13 8a5 5 0 1 1-1.5-3.6" {...stroke} /><path d="M13.4 2.8v2.8h-2.8" {...stroke} /></>,
    plus: <><path d="M8 3.6v8.8M3.6 8h8.8" {...stroke} /></>,
    key: <><circle cx="6" cy="10" r="3" {...stroke} /><path d="M8.2 8.2L13 3.4M11 5.6l1.6 1.6" {...stroke} /></>,
    edit: <><path d="M11.3 2.4l2.3 2.3-7.4 7.4-3 .7.7-3 7.4-7.4z" {...stroke} /></>,
    trash: <><path d="M3.4 4.6h9.2M6.4 4.6V3.1h3.2v1.5M4.8 4.6l.6 8.3h5.2l.6-8.3" {...stroke} /></>,
    undo: <><path d="M3.6 7.2V4.1M3.6 7.2h3.1" {...stroke} /><path d="M3.9 7a5 5 0 1 1 .6 4.4" {...stroke} /></>,
    close: <><path d="M4.2 4.2l7.6 7.6M11.8 4.2l-7.6 7.6" {...stroke} /></>,
    chevron: <><path d="M6 4l4 4-4 4" {...stroke} /></>,
    folder: <><path d="M2.2 4.4h4l1.2 1.6h6.4v6.4H2.2z" {...stroke} /></>,
    all: <><path d="M2.6 4.4h10.8M2.6 8h10.8M2.6 11.6h10.8" {...stroke} /></>,
    eye: <><path d="M1.6 8s2.4-4.2 6.4-4.2S14.4 8 14.4 8s-2.4 4.2-6.4 4.2S1.6 8 1.6 8Z" {...stroke} /><circle cx="8" cy="8" r="1.9" {...stroke} /></>,
    "eye-off": <><path d="M6.2 3.9c.6-.1 1.2-.2 1.8-.2 4 0 6.4 4.3 6.4 4.3a12 12 0 0 1-2.3 2.7M4 5.3A12 12 0 0 0 1.6 8s2.4 4.2 6.4 4.2c.9 0 1.7-.2 2.4-.5" {...stroke} /><path d="M2.6 2.6l10.8 10.8" {...stroke} /></>,
    copy: <><rect x="5.4" y="5.4" width="8" height="8" rx="1.5" {...stroke} /><path d="M10.6 5.4V4a1.4 1.4 0 0 0-1.4-1.4H4A1.4 1.4 0 0 0 2.6 4v5.2A1.4 1.4 0 0 0 4 10.6h1.4" {...stroke} /></>,
    clock: <><circle cx="8" cy="8" r="5.6" {...stroke} /><path d="M8 4.8V8l2.2 1.4" {...stroke} /></>,
    // A piece of a jigsaw: a plugin is the part that fits into the cut-out.
    puzzle: <><path d="M6.2 2.4h3.6v1.4a1.3 1.3 0 1 0 2.6 0V2.4h1.2v3.4h-1.4a1.3 1.3 0 1 0 0 2.6h1.4v3.4H10v-1.4a1.3 1.3 0 1 0-2.6 0v1.4H2.4V8.4h1.4a1.3 1.3 0 1 0 0-2.6H2.4V2.4h3.8Z" {...stroke} /></>,
    more: <><circle cx="3.6" cy="8" r="1.1" fill="currentColor" /><circle cx="8" cy="8" r="1.1" fill="currentColor" /><circle cx="12.4" cy="8" r="1.1" fill="currentColor" /></>,
    check: <><path d="M3 8.5l3.5 3.5L13 5" {...stroke} /></>,
    warn: <><path d="M8 2.6 14 13H2L8 2.6Z" {...stroke} /><path d="M8 6.6v3M8 11.2v.2" {...stroke} /></>,
    // An account's devices: what was logged in from.
    desktop: <><rect x="2.2" y="3" width="11.6" height="7.6" rx="1.4" {...stroke} /><path d="M5.6 13.2h4.8M8 10.6v2.6" {...stroke} /></>,
    mobile: <><rect x="4.6" y="2.2" width="6.8" height="11.6" rx="1.6" {...stroke} /><path d="M7.2 11.6h1.6" {...stroke} /></>,
    globe: <><circle cx="8" cy="8" r="5.6" {...stroke} /><path d="M2.4 8h11.2M8 2.4c-2 2-2 9.2 0 11.2M8 2.4c2 2 2 9.2 0 11.2" {...stroke} /></>,
    terminal: <><rect x="2.2" y="3" width="11.6" height="10" rx="1.6" {...stroke} /><path d="M4.8 6.2 7 8l-2.2 1.8M8.4 10h3" {...stroke} /></>,
    // Kubernetes' own dialect: what a cluster is made of.
    pod: <><path d="M8 2.2 13.4 5v6L8 13.8 2.6 11V5L8 2.2Z" {...stroke} /><path d="M2.6 5 8 7.8 13.4 5M8 7.8v6" {...stroke} /></>,
    layers: <><path d="M8 2.4 14 5.4 8 8.4 2 5.4 8 2.4Z" {...stroke} /><path d="M2 8.4l6 3 6-3M2 11.2l6 3 6-3" {...stroke} /></>,
    network: <><circle cx="8" cy="3.4" r="1.4" {...stroke} /><circle cx="3.4" cy="12.4" r="1.4" {...stroke} /><circle cx="12.6" cy="12.4" r="1.4" {...stroke} /><path d="M8 4.8v3.6M8 8.4 4.5 11.3M8 8.4l3.5 2.9" {...stroke} /></>,
    sliders: <><path d="M2.6 4.4h3M8.4 4.4h5M2.6 8h6.4M11.8 8h1.6M2.6 11.6h1.2M6.6 11.6h6.8" {...stroke} /><circle cx="7" cy="4.4" r="1.4" {...stroke} /><circle cx="10.4" cy="8" r="1.4" {...stroke} /><circle cx="5.2" cy="11.6" r="1.4" {...stroke} /></>,
    server: <><rect x="2.6" y="2.6" width="10.8" height="4.4" rx="1.2" {...stroke} /><rect x="2.6" y="9" width="10.8" height="4.4" rx="1.2" {...stroke} /><path d="M5 4.8h.4M5 11.2h.4" {...stroke} /></>,
    logs: <><path d="M3 4h10M3 6.8h7M3 9.6h10M3 12.4h5" {...stroke} /></>,
    code: <><path d="M6 4.4 2.6 8 6 11.6M10 4.4 13.4 8 10 11.6" {...stroke} /></>,
    bolt: <><path d="M9 1.8 3.6 9h4l-1 5.2L12.4 7h-4L9 1.8Z" {...stroke} /></>,
    link: <><path d="M6.6 9.4 9.4 6.6" {...stroke} /><path d="M7.4 4.6l1-1a2.4 2.4 0 0 1 3.4 3.4l-1 1M8.6 11.4l-1 1a2.4 2.4 0 0 1-3.4-3.4l1-1" {...stroke} /></>,
    database: <><ellipse cx="8" cy="4" rx="4.8" ry="1.8" {...stroke} /><path d="M3.2 4v8c0 1 2.1 1.8 4.8 1.8s4.8-.8 4.8-1.8V4M3.2 8c0 1 2.1 1.8 4.8 1.8s4.8-.8 4.8-1.8" {...stroke} /></>,
    grid: <><rect x="2.6" y="2.6" width="4.4" height="4.4" rx="1" {...stroke} /><rect x="9" y="2.6" width="4.4" height="4.4" rx="1" {...stroke} /><rect x="2.6" y="9" width="4.4" height="4.4" rx="1" {...stroke} /><rect x="9" y="9" width="4.4" height="4.4" rx="1" {...stroke} /></>,
    plug: <><path d="M6 2.4v3M10 2.4v3M4.4 5.4h7.2v2.4a3.6 3.6 0 0 1-7.2 0V5.4ZM8 11.4v2.2" {...stroke} /></>,
    "shield-check": <><path d="M8 1.7 13.3 3.7v4.1c0 3.1-2.1 5.7-5.3 6.9C4.8 13.5 2.7 10.9 2.7 7.8V3.7L8 1.7Z" {...stroke} /><path d="M5.8 8l1.6 1.6 3-3.2" {...stroke} /></>,
    // A cluster: a hub and the nodes round it.
    cluster: <><circle cx="8" cy="8" r="1.8" {...stroke} /><circle cx="8" cy="2.9" r="1.3" {...stroke} /><circle cx="12.4" cy="10.6" r="1.3" {...stroke} /><circle cx="3.6" cy="10.6" r="1.3" {...stroke} /><path d="M8 4.2v2M9.6 8.9l1.7 1M6.4 8.9l-1.7 1" {...stroke} /></>,
  };
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" aria-hidden="true" className="icon">
      {paths[name] ?? null}
    </svg>
  );
}

/* ── The error messages ───────────────────────────────────────────────
   An error has to say three things: what happened, what to do about it and,
   on demand, the raw text for a diagnosis. A red line with no way out is of
   no use. */

export function Alert({
  message,
  onRetry,
  onClose,
  tone = "error",
}: {
  message: string;
  onRetry?: () => void;
  /// The cross: an error that cannot be taken away turns the screen into a
  /// dead end.
  onClose?: () => void;
  tone?: "error" | "warn";
}) {
  const [open, setOpen] = useState(false);
  const human = tError(message);
  const raw = message.replace(/^Error:\s*/, "").trim();
  const hasDetails = raw !== human && raw.length > 0;

  return (
    <div className={`alert ${tone}`} role="alert">
      <Icon name="warn" />
      <div className="alert-body">
        <span>{human}</span>
        {open && hasDetails && <pre>{raw}</pre>}
        <div className="alert-actions">
          {onRetry && (
            <button type="button" className="link" onClick={onRetry}>
              {t("action.retry")}
            </button>
          )}
          {hasDetails && (
            <button type="button" className="link" onClick={() => setOpen((v) => !v)}>
              {t("action.details")}
            </button>
          )}
        </div>
      </div>
      {onClose && (
        <button type="button" className="btn icon-only alert-close" onClick={onClose} aria-label={t("detail.close")} title={t("detail.close")}>
          <Icon name="close" size={13} />
        </button>
      )}
    </div>
  );
}

/* ── The empty state ───────────────────────────────────────────────────
   Always with one action: an empty screen is an invitation, not a dead
   end. */

export function Empty({
  icon,
  title,
  body,
  action,
}: {
  icon: string;
  title: string;
  body?: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      <span className="empty-icon">
        <Icon name={icon} size={22} />
      </span>
      <h3>{title}</h3>
      {body && <p>{body}</p>}
      {action}
    </div>
  );
}

/* ── The loading skeleton ──────────────────────────────────────────────
   Shown in place of emptiness while the daemon answers: otherwise the first
   frame looks like "there is nothing here" and the wrong conclusion is
   drawn. */

export function Skeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="skeleton" aria-hidden="true">
      {Array.from({ length: rows }, (_, i) => (
        <div className="skeleton-row" key={i} style={{ animationDelay: `${i * 60}ms` }} />
      ))}
    </div>
  );
}

/* ── The modal window ──────────────────────────────────────────────────
   Escape closes it, a click on the backdrop closes it, the focus goes
   inside. These are expectations nobody puts into words but everybody
   notices the absence of. */


/// The arrows inside a group: one stop of the keyboard's walk for the whole
/// group.
///
/// `role="tablist"` promises the keyboard its arrows, and there were none:
/// instead of moving between sections, Tab stopped on every cell, and on the
/// second button Enter submitted the form.
function useRoving<T extends string>(value: T, options: { id: T }[], onChange: (id: T) => void) {
  return (e: React.KeyboardEvent) => {
    const step = e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : 0;
    if (step === 0) return;
    e.preventDefault();
    const at = options.findIndex((o) => o.id === value);
    const next = options[(at + step + options.length) % options.length];
    if (next) onChange(next.id);
  };
}


/*
  A field with hints from what is already in the vault.

  An email and a login repeat from item to item, and typing them again is work
  out of nothing: a person has three or four of them and hundreds of items. The
  list is taken from the catalogue, that is from what is already decrypted — no
  request of its own to the daemon is needed for it.

  Not a `datalist`: the native drop-down is drawn by the system and looks
  foreign in a dark window.
*/
export function Suggest({
  value,
  onChange,
  options,
  label,
  ...rest
}: {
  value: string;
  onChange: (v: string) => void;
  options: string[];
  label?: string;
} & Omit<React.InputHTMLAttributes<HTMLInputElement>, "value" | "onChange">) {
  const [open, setOpen] = useState(false);
  const [at, setAt] = useState(0);
  const box = useRef<HTMLDivElement>(null);

  // A login with no username comes as null from the card: the form must not
  // fall over on it.
  const text = value ?? "";
  const needle = text.trim().toLowerCase();
  const shown = options
    .filter((o) => o && o.toLowerCase() !== needle && (needle === "" || o.toLowerCase().includes(needle)))
    .slice(0, 8);

  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => {
      if (!box.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [open]);

  const take = (v: string) => {
    onChange(v);
    setOpen(false);
  };

  return (
    <div className="suggest" ref={box}>
      <input
        {...rest}
        value={text}
        aria-label={label}
        autoComplete="off"
        onChange={(e) => {
          onChange(e.target.value);
          setOpen(true);
          setAt(0);
        }}
        onFocus={() => setOpen(true)}
        onKeyDown={(e) => {
          if (!open || shown.length === 0) return;
          if (e.key === "ArrowDown" || e.key === "ArrowUp") {
            e.preventDefault();
            setAt((i) => (i + (e.key === "ArrowDown" ? 1 : -1) + shown.length) % shown.length);
          } else if (e.key === "Enter") {
            // A hint is chosen with the same Enter, but with the list open it
            // does not submit the form: the value first, the submission
            // after.
            e.preventDefault();
            e.stopPropagation();
            take(shown[at]);
          } else if (e.key === "Escape" && open) {
            // The hints go first; the dialogue around stays.
            e.preventDefault();
            setOpen(false);
          }
        }}
      />
      {open && shown.length > 0 && (
        <div className="suggest-list" role="listbox">
          {shown.map((o, i) => (
            <button
              key={o}
              type="button"
              role="option"
              aria-selected={i === at}
              className={i === at ? "on" : ""}
              onMouseEnter={() => setAt(i)}
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => take(o)}
            >
              {o}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/*
  Escape, one rule for the whole application: it closes whatever was opened
  last, and only that.

  Every open thing — a dialogue, a drop-down, the search, the drawer, the
  account's menu, an item's card, a plugin's page over its list — registers
  here while it is open, and one listener hands Escape to the topmost. They
  used to listen each for itself on the document, where stopPropagation does
  not work between listeners, so one Escape closed a dialogue and the card
  under it together; and some listened not at all.

  An element that consumes Escape itself first — an editor's completion, a
  field's hints — calls preventDefault, and then nothing here moves.
*/
const escapers: { id: symbol; close: () => void }[] = [];
let escapeInstalled = false;

function installEscape() {
  if (escapeInstalled) return;
  escapeInstalled = true;
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape" || e.defaultPrevented) return;
    const top = escapers[escapers.length - 1];
    if (!top) return;
    e.preventDefault();
    top.close();
  });
}

/// Close this on Escape while `close` is given; `null` is "not open now".
export function useEscape(close: (() => void) | null | undefined) {
  const ref = useRef(close);
  ref.current = close;
  const open = Boolean(close);
  useEffect(() => {
    if (!open) return;
    installEscape();
    const id = Symbol("escape");
    escapers.push({ id, close: () => ref.current?.() });
    return () => {
      const at = escapers.findIndex((x) => x.id === id);
      if (at !== -1) escapers.splice(at, 1);
    };
  }, [open]);
}

/*
  The stack of open windows.

  Only the topmost keeps the keyboard's walk inside itself (Escape goes through the one stack above). Both handlers
  hang on the document, and `stopPropagation` does not work between listeners on
  one element — without the stack, Escape in the generator on top of an item's
  form closed both the generator and the form.
*/
const stack: symbol[] = [];

/*
  The order the windows stack in.

  Both windows are ported into the root of the document, and at an equal z-index
  whatever comes later in the markup ends up on top. The order they are added in
  is React's, and it is the reverse of what is expected: a generator inside an
  item's form commits before the form itself and ended up underneath it. The
  counter is assigned in the component's body, so that whatever was opened last
  is always on top.
*/
let seq = 100;

/// What counts as a stop of the keyboard's walk inside a window.
const FOCUSABLE =
  'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';

export function Modal({
  title,
  onClose,
  onSubmit,
  children,
  footer,
  wide = false,
  full = false,
}: {
  title: string;
  onClose: () => void;
  /// Enter in a single-line field confirms — as in any system dialogue.
  onSubmit?: () => void;
  children: ReactNode;
  footer?: ReactNode;
  /// A wide dialogue — for forms whose fields stand in pairs.
  wide?: boolean;
  /// The full screen — for editing an item: there are many fields, and there
  /// is no point squeezing them into a little box in the middle of the
  /// window.
  full?: boolean;
}) {
  const box = useRef<HTMLDivElement>(null);
  const me = useRef<symbol>(Symbol("modal"));
  const [z] = useState(() => (seq += 1));

  useEffect(() => {
    const id = me.current;
    stack.push(id);
    return () => {
      const at = stack.indexOf(id);
      if (at !== -1) stack.splice(at, 1);
    };
  }, []);

  const topmost = () => stack[stack.length - 1] === me.current;

  /*
    Escape closes the dialogue through the one stack; Enter is not caught.

    Enter used to be caught here as well, and any press outside a multi-line
    field meant "submit". The search inside the folders' drop-down is ported
    into the root of the document and fell under the same handler: a folder
    was chosen and a created item came back. The tabs' buttons and the kind
    picker too: instead of switching, a submission happened. Now Enter is the
    form's business, and only the button declared the main one confirms it.
  */
  useEscape(onClose);

  // The focus does not leave the window while it is open, and goes back where
  // it came from. Without that Shift+Tab from the first field led into the
  // shell under the dialogue — into the list of items, which must not be
  // touched at that moment.
  useEffect(() => {
    const came = document.activeElement as HTMLElement | null;
    const onTab = (e: KeyboardEvent) => {
      if (e.key !== "Tab" || !box.current || !topmost()) return;
      const stops = [...box.current.querySelectorAll<HTMLElement>(FOCUSABLE)].filter(
        (el) => !el.hasAttribute("disabled") && el.tabIndex !== -1,
      );
      if (stops.length === 0) return;
      const first = stops[0];
      const last = stops[stops.length - 1];
      const active = document.activeElement;
      if (e.shiftKey && (active === first || !box.current.contains(active))) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && active === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onTab, true);
    return () => {
      document.removeEventListener("keydown", onTab, true);
      came?.focus?.();
    };
  }, []);

  // Drawn in the root of the document rather than where it was called.
  //
  // `position: fixed` counts not from the window but from the nearest ancestor
  // that sets a coordinate system for it — and any element with a transform
  // becomes such an ancestor. An item's card has an appearance animation, so
  // the edit form opened inside the card and travelled past its right edge,
  // where it was cut off. The portal takes that dependency away entirely:
  // wherever the dialogue is called, it is on top of the whole window.
  return createPortal(
    <div
      className="scrim"
      style={{ zIndex: z }}
      onMouseDown={(e) => e.target === e.currentTarget && onClose()}
    >
      <div
        ref={box}
        className={`modal ${wide ? "wide" : ""} ${full ? "full" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <header>
          <h3>{title}</h3>
          <button className="btn icon-only" type="button" onClick={onClose} aria-label={t("detail.close")}>
            <Icon name="close" size={14} />
          </button>
        </header>
        {/* A form rather than a div: Enter confirms by the browser's own means,
            and only from the fields it ought to confirm from. */}
        {onSubmit ? (
          <form
            className="body"
            onSubmit={(e) => {
              e.preventDefault();
              onSubmit();
            }}
          >
            {children}
            {/* A hidden submit button: the main action lives in the footer,
                outside the form, so Enter has to catch on to something. */}
            <button type="submit" className="submit-proxy" tabIndex={-1} aria-hidden="true" />
          </form>
        ) : (
          // Nothing to confirm with Enter: the contents may hold forms of
          // their own, and a form inside a form is not one.
          <div className="body">{children}</div>
        )}
        {footer && <footer>{footer}</footer>}
      </div>
    </div>,
    document.body,
  );
}

/* ── The toasts ────────────────────────────────────────────────────────
   They live outside the screens' tree, so that switching sections does not
   clear them. */

/// A toast's look: what happened, said by its icon and colour as well as by
/// its words.
export type ToastKind = "ok" | "trash" | "restore" | "error" | "copy" | "info";
export type Toast = { id: number; text: string; kind: ToastKind; leaving?: boolean };

const TOAST_ICON: Record<ToastKind, string> = { ok: "check", trash: "trash", restore: "undo", error: "warn", copy: "copy", info: "shield" };

export function useToasts() {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const push = useCallback((text: string, kind: ToastKind = "ok") => {
    const id = Date.now() + Math.random();
    setToasts((list) => [...list, { id, text, kind }]);
    // Leaving is quicker than arriving: the system answers quickly, the
    // person decides.
    setTimeout(() => setToasts((l) => l.map((x) => (x.id === id ? { ...x, leaving: true } : x))), 2600);
    setTimeout(() => setToasts((l) => l.filter((x) => x.id !== id)), 2760);
  }, []);

  return { toasts, push };
}

export function Toasts({ toasts }: { toasts: Toast[] }) {
  if (toasts.length === 0) return null;
  return (
    <div className="toasts">
      {toasts.map((x) => (
        <div className={`toast toast-${x.kind} ${x.leaving ? "leaving" : ""}`} key={x.id} role="status">
          <span className="toast-icon">
            <Icon name={TOAST_ICON[x.kind]} size={14} />
          </span>
          {x.text}
        </div>
      ))}
    </div>
  );
}

/* ── The drop-down with a search ───────────────────────────────────────
   A system <select> over a hundred entries is of no use: there is no
   searching in it, and it looks foreign. */

export function Picker({
  value,
  options,
  placeholder,
  onChange,
  picked,
  onUnpick,
}: {
  value: string | null;
  options: { id: string; label: string; hint?: string }[];
  placeholder: string;
  onChange: (id: string) => void;
  /// What has been chosen already, when several may be. The chips sit inside
  /// the control: a choice of many is one control, not a control with a list
  /// hanging underneath that grows the block every time something is added.
  /// `hint` becomes the chip's tooltip — that is where a long explanation
  /// goes, instead of on the screen beside the name.
  picked?: { id: string; label: string; hint?: string }[];
  onUnpick?: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [rect, setRect] = useState<{ left: number; top: number; width: number; up: boolean } | null>(null);
  const box = useRef<HTMLDivElement | null>(null);
  const menu = useRef<HTMLDivElement | null>(null);

  // The list is drawn in the root of the document rather than inside the
  // field.
  //
  // Absolute positioning inside works exactly as far as the first ancestor with
  // overflow: hidden — and there is almost always one in this application,
  // because every column scrolls on its own. The list was cut off at the
  // column's edge, and the names had their first letters bitten off.
  useLayoutEffect(() => {
    if (!open) return;
    const place = () => {
      const r = box.current?.getBoundingClientRect();
      if (!r) return;
      const room = window.innerHeight - r.bottom;
      const up = room < 260 && r.top > room;
      setRect({
        left: Math.min(r.left, window.innerWidth - r.width - 8),
        top: up ? r.top - 6 : r.bottom + 6,
        width: r.width,
        up,
      });
    };
    place();
    window.addEventListener("resize", place);
    window.addEventListener("scroll", place, true);
    return () => {
      window.removeEventListener("resize", place);
      window.removeEventListener("scroll", place, true);
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => {
      const target = e.target as Node;
      if (box.current?.contains(target) || menu.current?.contains(target)) return;
      setOpen(false);
    };
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [open]);
  useEscape(open ? () => setOpen(false) : null);

  const chosen = options.find((o) => o.id === value);
  const q = query.trim().toLowerCase();
  const shown = q ? options.filter((o) => o.label.toLowerCase().includes(q)) : options;

  const chips = picked ?? [];

  return (
    <div className="picker" ref={box}>
      {chips.length > 0 ? (
        // A div rather than a button: the chips are buttons themselves, and a
        // button inside a button is neither valid markup nor something a screen
        // reader can make sense of. The whole strip opens the list on a click;
        // for the keyboard there is a button of its own at the end.
        <div className="picker-value picked" onClick={() => setOpen((v) => !v)}>
          {chips.map((c) => (
            <button
              type="button"
              key={c.id}
              className="chip pick"
              title={c.hint || c.label}
              onClick={(e) => {
                e.stopPropagation();
                onUnpick?.(c.id);
              }}
            >
              <span className="txt">{c.label}</span>
              <span className="x">×</span>
            </button>
          ))}
          <button
            type="button"
            className="picker-open"
            aria-label={placeholder}
            aria-expanded={open}
            onClick={(e) => {
              e.stopPropagation();
              setOpen((v) => !v);
            }}
          >
            <span className="dim">{placeholder}</span>
            <Icon name="chevron" size={13} />
          </button>
        </div>
      ) : (
        <button type="button" className="picker-value" onClick={() => setOpen((v) => !v)}>
          <span className={chosen ? "" : "dim"}>{chosen?.label ?? placeholder}</span>
          <Icon name="chevron" size={13} />
        </button>
      )}

      {open &&
        rect &&
        createPortal(
          <div
            ref={menu}
            className={`picker-menu ${rect.up ? "up" : ""}`}
            // Above any open dialogue: their z-index grows with the counter,
            // and a fixed value from the CSS ended up under the window — the
            // menu opened, but the window was what got clicked.
            style={{ left: rect.left, top: rect.top, minWidth: Math.min(rect.width, 480), zIndex: seq + 1 }}
          >
            <label className="picker-search">
              <Icon name="search" size={13} />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={t("action.search")}
                autoFocus
                spellCheck={false}
                onKeyDown={(e) => {
                  // Enter chooses the first match. It used to bubble up to the
                  // dialogue and submit the form: a folder was searched for and
                  // a created item came back.
                  if (e.key !== "Enter") return;
                  e.preventDefault();
                  e.stopPropagation();
                  const first = shown[0];
                  if (!first) return;
                  onChange(first.id);
                  setOpen(false);
                  setQuery("");
                }}
              />
            </label>
            <div className="picker-list">
              {shown.length === 0 && <div className="picker-empty">{t("items.empty")}</div>}
              {shown.map((o) => (
                <button
                  key={o.id}
                  type="button"
                  className={`picker-option ${o.id === value ? "on" : ""}`}
                  onClick={() => {
                    onChange(o.id);
                    setOpen(false);
                    setQuery("");
                  }}
                >
                  <span>{o.label}</span>
                  {o.hint && <span className="hint">{o.hint}</span>}
                </button>
              ))}
            </div>
          </div>,
          document.body,
        )}
    </div>
  );
}

/// A block that unfolds, for what is optional.
///
/// Made by hand rather than with `<details>`: the native one draws a triangle
/// of its own and lives by its own spacing, and there is nothing like that in
/// the rest of the application.
/// An icon of our own for an item with no favicon: one or two letters of the
/// name on a colour derived from the name itself. One and the same item always
/// looks the same — in the list, in the header, after a restart.
/// An item's hue from its name — the same as the monogram's, so that the
/// item's card can pick it up as an accent.
export function nameHue(name: string): number {
  let h = 0;
  for (const ch of name) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  // The blue-violet arc (195°–310°) is thrown out of the circle: monograms
  // like that read as the blue and lilac accents the palette no longer has.
  // The remaining 245° are stretched over the whole range of the hash, so that
  // the spread does not suffer.
  const hue = h % 245;
  return hue < 195 ? hue : hue + 115;
}

export function Monogram({ name, size = 28, className = "" }: { name: string; size?: number; className?: string }) {
  // Letters and digits only: "[Backup] Gmail" is BG rather than "[G".
  const words = name
    .split(/[^\p{L}\p{N}]+/u)
    .filter(Boolean);
  const letters = (words.length >= 2 ? words[0][0] + words[1][0] : (words[0] ?? "?").slice(0, 2)).toUpperCase();
  const hue = nameHue(name);
  return (
    <span
      className={`monogram ${className}`}
      style={{ ["--h" as string]: String(hue), width: size, height: size, fontSize: Math.round(size * 0.42) }}
      aria-hidden="true"
    >
      {letters}
    </span>
  );
}

/// The destructive actions live in a block of their own at the bottom of a
/// card rather than in the footer next to "Save": each has a line of its own
/// with an explanation, and a button on the right.
export function DangerZone({
  title,
  items,
}: {
  title: string;
  items: { label: string; hint: string; action: string; onClick: () => void; disabled?: boolean; tone?: "danger" | "warn" }[];
}) {
  if (items.length === 0) return null;
  return (
    <section className="danger-zone">
      <h4>{title}</h4>
      {items.map((it) => (
        <div className="danger-row" key={it.label}>
          <span className="text">
            <b>{it.label}</b>
            <span className="hint">{it.hint}</span>
          </span>
          <button type="button" className={it.tone === "warn" ? "btn warn" : "btn danger"} disabled={it.disabled} onClick={it.onClick}>
            {it.action}
          </button>
        </div>
      ))}
    </section>
  );
}

export function Disclosure({ title, children, open: initial = false }: { title: string; children: ReactNode; open?: boolean }) {
  const [open, setOpen] = useState(initial);
  return (
    <div className={`disclosure${open ? " open" : ""}`}>
      <button type="button" className="disclosure-head" onClick={() => setOpen((v) => !v)}>
        <Icon name="chevron" size={12} />
        <span>{title}</span>
      </button>
      {open && <div className="disclosure-body">{children}</div>}
    </div>
  );
}

/// The switch between sections inside a view.
///
/// Ours rather than a set of buttons: the backing travels to the chosen one, and
/// that is what shows it to be one switch rather than three separate actions.
/*
  Moving between sections is not choosing a value.

  `Segmented` used to draw both, and in the form for creating an item two
  identical controls stood one under the other: choosing the item's kind and
  moving to the custom fields. The second read as a continuation of the first,
  which is why the custom fields "were not there" — there was simply nothing to
  take them for.
*/
/// The highlight of the active entry travels between the buttons rather than
/// jumping. The active button is measured and one element is moved with a
/// transform: the GPU alone.
function useInk(active: string, deps: unknown[] = []) {
  const box = useRef<HTMLDivElement | null>(null);
  const [ink, setInk] = useState<{ x: number; w: number; ready: boolean }>({ x: 0, w: 0, ready: false });
  const measure = useCallback(() => {
    const el = box.current?.querySelector<HTMLElement>('[data-active="true"]');
    if (!el || !box.current) return;
    const b = box.current.getBoundingClientRect();
    const r = el.getBoundingClientRect();
    setInk((cur) => (cur.ready && cur.x === r.left - b.left && cur.w === r.width ? cur : { x: r.left - b.left, w: r.width, ready: true }));
  }, []);
  useLayoutEffect(measure, [measure, active, ...deps]);
  // Measured once, the backing stayed where the tabs were before the font
  // came in or the column narrowed, and moved under its tab only on a click.
  // It follows every change of the tabs' size, and the fonts' arrival.
  useEffect(() => {
    if (!box.current) return;
    const ro = new ResizeObserver(measure);
    ro.observe(box.current);
    for (const c of box.current.children) ro.observe(c);
    void document.fonts?.ready.then(measure);
    return () => ro.disconnect();
  }, [measure, ...deps]);
  return { box, ink };
}

/// A copy button that answers: for a moment it turns into a tick.
/// Every copy goes through the daemon, never the webview's clipboard: the
/// daemon marks the entry concealed, so clipboard managers do not file it, and
/// clears it after the settings' interval. Returns the seconds until then.
export function copyText(value: string): Promise<number> {
  return invoke<number>("copy_text", { value });
}

export function CopyButton({ value, onCopied, title, size = 13, className = "btn icon-only", disabled }: { value: string; onCopied: (text: string) => void; title: string; size?: number; className?: string; disabled?: boolean }) {
  const [done, setDone] = useState(false);
  const timer = useRef<number | null>(null);
  useEffect(() => () => { if (timer.current !== null) window.clearTimeout(timer.current); }, []);
  return (
    <button
      type="button"
      className={`${className} copy-btn${done ? " done" : ""}`}
      title={title}
      aria-label={title}
      disabled={disabled}
      onClick={() => {
        void copyText(value).then(() => onCopied(t("action.copied")));
        setDone(true);
        if (timer.current !== null) window.clearTimeout(timer.current);
        timer.current = window.setTimeout(() => setDone(false), 1200);
      }}
    >
      <span className="copy-icon" aria-hidden="true"><Icon name="copy" size={size} /></span>
      <span className="copy-check" aria-hidden="true"><Icon name="check" size={size} /></span>
    </button>
  );
}

export function Tabs<T extends string>({
  value,
  options,
  onChange,
}: {
  value: T;
  /// `title` is the word of an option drawn as an icon alone.
  options: { id: T; label: string; count?: number; icon?: string; title?: string }[];
  onChange: (id: T) => void;
}) {
  const onKeyDown = useRoving(value, options, onChange);
  const { box, ink } = useInk(value, [options.length]);

  return (
    <div className="tabs" role="tablist" onKeyDown={onKeyDown} ref={box}>
      {ink.ready && <span className="ink" aria-hidden="true" style={{ transform: `translateX(${ink.x}px)`, width: ink.w }} />}
      {options.map((o) => (
        <button
          key={o.id}
          type="button"
          role="tab"
          aria-selected={o.id === value}
          data-active={o.id === value}
          tabIndex={o.id === value ? 0 : -1}
          className={o.id === value ? "on" : ""}
          title={o.title}
          aria-label={o.title}
          onClick={() => onChange(o.id)}
        >
          {o.icon && <Icon name={o.icon} size={13} />}
          {o.label}
          {o.count !== undefined && <span className="tally">{o.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function Segmented<T extends string>({
  value,
  options,
  onChange,
}: {
  value: T;
  /// `title` is the word of an option drawn as an icon alone.
  options: { id: T; label: string; count?: number; icon?: string; title?: string }[];
  onChange: (id: T) => void;
}) {
  const onKeyDown = useRoving(value, options, onChange);
  const { box, ink } = useInk(value, [options.length]);

  return (
    <div className="segmented" role="tablist" onKeyDown={onKeyDown} ref={box}>
      {ink.ready && <span className="ink" aria-hidden="true" style={{ transform: `translateX(${ink.x}px)`, width: ink.w }} />}
      {options.map((o) => (
        <button
          key={o.id}
          type="button"
          data-active={o.id === value}
          role="tab"
          aria-selected={o.id === value}
          tabIndex={o.id === value ? 0 : -1}
          className={o.id === value ? "on" : ""}
          title={o.title}
          aria-label={o.title}
          onClick={() => onChange(o.id)}
        >
          {o.icon && <Icon name={o.icon} size={13} />}
          {o.label}
          {o.count !== undefined && <span className="tally">{o.count}</span>}
        </button>
      ))}
    </div>
  );
}

/// A screen's head — one for every screen, drawer and dialogue of the app,
/// the core's and the plugins' alike: the title (or what stands for it, such
/// as a switcher) and the actions on one line at the controls' height, the
/// subtitle under it.
export function ScreenHead({
  icon,
  title,
  count,
  lead,
  subtitle,
  children,
}: {
  icon?: string;
  title?: ReactNode;
  count?: number;
  /// In place of the title: a switcher, a back button before it.
  lead?: ReactNode;
  subtitle?: ReactNode;
  /// The actions, at the right.
  children?: ReactNode;
}) {
  return (
    <header className="screen-head">
      <div className="screen-head-row">
        {lead}
        {title !== undefined && (
          <h3 className="screen-head-title">
            {icon && <Icon name={icon} size={16} />}
            <span className="screen-head-text">{title}</span>
            {count !== undefined && <Count n={count} className="screen-head-count" />}
          </h3>
        )}
        <span className="grow" />
        {children}
      </div>
      {subtitle && <p className="screen-head-sub">{subtitle}</p>}
    </header>
  );
}

/// The yes/no switch.
/// Several email addresses as chips: picked from `options` as one types, or
/// typed whole and taken on Enter, a comma or a space. Backspace in an empty
/// field takes the last chip back.
export function EmailChips({
  value,
  onChange,
  options,
  placeholder,
  autoFocus,
}: {
  value: string[];
  onChange: (v: string[]) => void;
  options: string[];
  placeholder?: string;
  autoFocus?: boolean;
}) {
  const [text, setText] = useState("");
  const [at, setAt] = useState(0);
  const q = text.trim().toLowerCase();
  const chosen = new Set(value.map((v) => v.toLowerCase()));
  const hints = options.filter((o) => !chosen.has(o.toLowerCase()) && (!q || o.toLowerCase().includes(q))).slice(0, 8);
  const add = (email: string) => {
    const e = email.trim().replace(/[,;]+$/, "");
    if (!e.includes("@") || chosen.has(e.toLowerCase())) return;
    onChange([...value, e]);
    setText("");
    setAt(0);
  };
  return (
    <div className="email-chips">
      <div className="email-chips-box">
        {value.map((v) => (
          <span className="fchip on" key={v}>
            {v}
            <button type="button" aria-label="×" onClick={() => onChange(value.filter((x) => x !== v))}>
              <Icon name="close" size={10} />
            </button>
          </span>
        ))}
        <input
          value={text}
          autoFocus={autoFocus}
          placeholder={value.length ? "" : placeholder}
          spellCheck={false}
          onChange={(e) => {
            const t = e.target.value;
            // A pasted list, or a separator typed: take what came before it.
            if (/[,;\s]/.test(t)) {
              const parts = t.split(/[,;\s]+/);
              const last = parts.pop() ?? "";
              const fresh = parts.map((p) => p.trim()).filter((p) => p.includes("@") && !chosen.has(p.toLowerCase()));
              if (fresh.length) onChange([...value, ...fresh]);
              setText(last);
            } else setText(t);
            setAt(0);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              e.stopPropagation();
              if (hints.length && (q === "" || !q.includes("@") || hints[at])) add(hints[at] ?? text);
              else add(text);
            } else if (e.key === "Backspace" && text === "" && value.length) {
              onChange(value.slice(0, -1));
            } else if ((e.key === "ArrowDown" || e.key === "ArrowUp") && hints.length) {
              e.preventDefault();
              setAt((i) => (i + (e.key === "ArrowDown" ? 1 : -1) + hints.length) % hints.length);
            }
          }}
        />
      </div>
      {hints.length > 0 && (
        <div className="email-chips-hints" role="listbox">
          {hints.map((h, i) => (
            <button key={h} type="button" role="option" aria-selected={i === at} className={i === at ? "on" : ""} onMouseDown={(e) => e.preventDefault()} onClick={() => add(h)}>
              <Icon name="plus" size={11} />
              {h}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/// A whole number with its own stepper: − and + beside the field, ↑/↓ by one
/// and with Shift by ten. Empty means "not set" — the default then shows as
/// the placeholder — and the browser's own tiny arrows are hidden.
export function NumberInput({
  value,
  onChange,
  placeholder,
  min,
  ariaLabel,
}: {
  value: number | null;
  onChange: (v: number | null) => void;
  placeholder?: string;
  min?: number;
  ariaLabel?: string;
}) {
  const clamp = (n: number) => (min !== undefined && n < min ? min : n);
  const base = () => value ?? (placeholder !== undefined && placeholder !== "" && !Number.isNaN(Number(placeholder)) ? Number(placeholder) : 0);
  const step = (by: number) => onChange(clamp(base() + by));
  return (
    <div className="stepper">
      <button type="button" className="stepper-btn" tabIndex={-1} aria-label="−" onClick={() => step(-1)} disabled={min !== undefined && base() <= min}>
        <span aria-hidden="true">−</span>
      </button>
      <input
        inputMode="numeric"
        value={value === null ? "" : String(value)}
        placeholder={placeholder}
        aria-label={ariaLabel}
        spellCheck={false}
        onChange={(e) => {
          const t = e.target.value.replace(/[^0-9-]/g, "");
          if (t === "" || t === "-") onChange(null);
          else if (!Number.isNaN(Number(t))) onChange(clamp(Math.trunc(Number(t))));
        }}
        onKeyDown={(e) => {
          if (e.key === "ArrowUp" || e.key === "ArrowDown") {
            e.preventDefault();
            step((e.key === "ArrowUp" ? 1 : -1) * (e.shiftKey ? 10 : 1));
          }
        }}
      />
      <button type="button" className="stepper-btn" tabIndex={-1} aria-label="+" onClick={() => step(1)}>
        <span aria-hidden="true">+</span>
      </button>
    </div>
  );
}

export function Toggle({ on, onChange }: { on: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      type="button"
      className={`switch ${on ? "on" : ""}`}
      role="switch"
      aria-checked={on}
      aria-label={t(on ? "toggle.on" : "toggle.off")}
      onClick={() => onChange(!on)}
    >
      <span />
    </button>
  );
}

/// Dark or light text on an arbitrary colour — by the background's
/// brightness.
export function inkOn(hex: string): string {
  const m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex);
  if (!m) return "var(--on-accent)";
  const [r, g, b] = [m[1], m[2], m[3]].map((x) => parseInt(x, 16) / 255);
  const lum = 0.2126 * r + 0.7152 * g + 0.0722 * b;
  // The theme's own inks, not colours of our own.
  return lum > 0.55 ? "var(--on-bright)" : "var(--on-accent)";
}

/* ── The bricks of the settings page ────────────────────────────────────
   The plugins' sections need them too: a block of one's own in the settings
   is drawn by the same hands as ours, or two blocks side by side look as if
   they came from different applications. */

/// A block of meaning across the full width: a heading in small capitals and a
/// coloured edge on the left.
export function Section({ title, tone, children }: { title: string; tone?: "mint" | "amber" | "orange"; children: ReactNode }) {
  return (
    <section className={`block ${tone ? `tone-${tone}` : ""}`}>
      <h4 className="block-title">{title}</h4>
      {children}
    </section>
  );
}

/// A "name — control" row. The hint explains the consequences rather than
/// repeating the heading.
export function Row({ title, hint, children }: { title: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <div className="between setting">
      <div className="setting-text">
        <h3>{title}</h3>
        {hint && <p>{hint}</p>}
      </div>
      {children}
    </div>
  );
}

export function Rows({ children }: { children: ReactNode }) {
  return <div className="rows">{children}</div>;
}

/// A "field — value" row: reading only.
export function Field({ label, value, mono = true }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="kv">
      <span className="k">{label}</span>
      <span className={`v ${mono ? "mono" : ""}`}>{value}</span>
    </div>
  );
}

/// Whether the person asked the system for less motion.
export function lessMotion(): boolean {
  return window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
}

/// A change of what is on screen, drawn as a movement rather than a jump:
/// a row that leaves folds away and the rest slide into its place. The
/// browser's view transitions do the work where there are any; elsewhere, and
/// for a person who asked for less motion, the change is simply made.
export function withTransition(change: () => void): void {
  const start = (document as Document & { startViewTransition?: (cb: () => void) => unknown }).startViewTransition;
  if (!start || lessMotion()) {
    change();
    return;
  }
  start.call(document, () => flushSync(change));
}

/// A thin running bar under the top band while something is under way that
/// the person is waiting on: a write the server has not confirmed, a sync.
export function ActivityBar({ on }: { on: boolean }) {
  return <div className={`activity ${on ? "on" : ""}`} role="progressbar" aria-hidden={!on} aria-busy={on} />;
}

/// A number that hops when it changes — never on its first showing, or every
/// count would hop at once when the window opens.
export function Count({ n, className = "count" }: { n: number; className?: string }) {
  const first = useRef(n);
  const [hop, setHop] = useState(0);
  useEffect(() => {
    if (n !== first.current) setHop((h) => h + 1);
    first.current = n;
  }, [n]);
  return (
    <span className={`${className} ${hop ? "hop" : ""}`} key={hop}>
      {n}
    </span>
  );
}

/// A colour token of the theme as it is now. A token that is not there is a
/// mistake in the theme, said loudly, never papered over with a colour of
/// our own.
export function themeToken(name: string): string {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  if (!v) console.error(`keyward: the theme has no ${name}`);
  return v;
}

/// The same colour, partly see-through: `#rrggbb` + an alpha byte; anything
/// else as it is.
function seeThrough(color: string, alpha: string): string {
  return /^#[0-9a-f]{6}$/i.test(color) ? `${color}${alpha}` : color;
}

/// A terminal's colours, every one of them the theme's: the ground, the words,
/// the cursor in the accent, the sixteen colours of the shell from the
/// theme's own reds, greens and blues — in the light theme and the dark one.
export function terminalTheme() {
  const ground = themeToken("--block");
  const text = themeToken("--text");
  const dim = themeToken("--dim");
  const faint = themeToken("--faint");
  const raise = themeToken("--raise");
  const accent = themeToken("--sky");
  const isLight = window.matchMedia?.("(prefers-color-scheme: light)").matches ?? false;
  const red = themeToken("--rose");
  const green = themeToken("--mint");
  const yellow = themeToken("--amber");
  const blue = themeToken("--blue-hi");
  const orange = themeToken("--orange");
  const cyan = themeToken("--cyan");
  return {
    background: ground,
    foreground: text,
    cursor: accent,
    cursorAccent: ground,
    selectionBackground: seeThrough(accent, "55"),
    black: isLight ? text : raise,
    red,
    green,
    yellow,
    blue,
    magenta: accent,
    cyan,
    white: isLight ? faint : dim,
    brightBlack: faint,
    brightRed: red,
    brightGreen: green,
    brightYellow: orange,
    brightBlue: blue,
    brightMagenta: accent,
    brightCyan: cyan,
    brightWhite: isLight ? dim : text,
  };
}

/// Calls `change` whenever the theme changes under a running screen: the
/// system's light or dark, a palette or accent picked in the settings.
/// Returns the unsubscribe.
export function onThemeChange(change: () => void): () => void {
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  media.addEventListener("change", change);
  const watcher = new MutationObserver(change);
  watcher.observe(document.documentElement, { attributes: true, attributeFilter: ["style", "class", "data-theme"] });
  return () => {
    media.removeEventListener("change", change);
    watcher.disconnect();
  };
}
