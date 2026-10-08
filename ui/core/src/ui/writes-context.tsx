// The window's writes: what an app gives the core to change a vault, and
// the state of the changes under way. An item's draft is its document's own
// state (editing does not move the line); a saved edit is shown at once and
// taken back with a word if the backend refuses; a new item or folder is
// stepped onto once the catalogue has it. Without writes the window offers
// none of this.
import { faultWords } from "./fault";
import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { DEFAULT_GENERATOR, draftOf, fillSecrets, problems, type Form } from "../edit/draft";
import { t } from "../i18n";
import type { Directory } from "../path/directory";
import { type Effect, FolderOp } from "../verbs/spec";
import { runFolderWrite } from "../verbs/writes";
import { land, type Landing } from "../edit/landing";
import { Refills, type Refill } from "../edit/refill";
import { orgLanding, runOrgWrite, withShownFingerprint } from "../verbs/org";
import { GeneratorKind, type GeneratorOptions, type ItemDraft, type Writes } from "../writes";
import { useCore } from "./marks";

/// A saved edit the backend has not answered yet: the page shows it.
export type Pending = { itemId: string; draft: ItemDraft };
/// A member's fingerprint as the window has it: on its way, on screen, or
/// refused with the backend's reason.
export enum FingerprintPhase {
  Loading = "loading",
  Shown = "shown",
  Failed = "failed",
}
export type ShownFingerprint = { phase: FingerprintPhase.Loading } | { phase: FingerprintPhase.Shown; words: string[] } | { phase: FingerprintPhase.Failed; error: unknown };
export type GenPrefs = { kind: GeneratorKind; password: Extract<GeneratorOptions, { kind: GeneratorKind.Password }>; passphrase: Extract<GeneratorOptions, { kind: GeneratorKind.Passphrase }> };

export type WritesApi = {
  writes: Writes;
  /// The item whose document is a form now.
  editing: string | null;
  startEdit: (itemId: string) => void;
  /// A form by its key: `edit:<item id>` or `new:<node id>`.
  form: (key: string) => Form | null;
  setForm: (key: string, f: Form) => void;
  cancel: (key: string) => void;
  /// Saves a form with the secrets its fields gave up for it (by slot id);
  /// they cross to the backend inside the draft and are not kept.
  save: (key: string, typed: ReadonlyMap<string, string>) => Promise<void>;
  /// What a refused save took from a form's fields, handed back once so the
  /// fields can be filled again; the form asks for it when it is drawn and
  /// whenever `refillTurn` moves (a refused new item's form stays drawn).
  refill: (key: string) => Refill | null;
  refillTurn: (key: string) => number;
  /// The form being saved, while the backend works.
  saving: string | null;
  pending: Pending | null;
  /// Runs a write's effect; `null` for an effect that is not a write's.
  /// A confirm goes with the fingerprint on screen for that member, or not
  /// at all.
  perform: (e: Effect) => Promise<boolean> | null;
  /// A member's fingerprint while a preview shows it: fetched afresh when
  /// shown (`showFingerprint`), forgotten when it is not (`hideFingerprint`).
  fingerprint: (orgId: string, memberId: string) => ShownFingerprint | null;
  showFingerprint: (orgId: string, memberId: string) => void;
  hideFingerprint: (orgId: string, memberId: string) => void;
  gen: GenPrefs;
  setGen: (g: GenPrefs) => void;
};

const WritesContext = createContext<WritesApi | null>(null);
/// The window's writes, or `null` where the app gives none.
export const useWrites = () => useContext(WritesContext);


/// A refusal's words: the dictionary's when it is one of its `err.*` keys.
const reason = faultWords;

export function WritesProvider({ writes, children }: { writes: Writes | null; children: ReactNode }) {
  if (!writes) return <>{children}</>;
  return <Provider writes={writes}>{children}</Provider>;
}

function Provider({ writes, children }: { writes: Writes; children: ReactNode }) {
  const { dir, store, report } = useCore();
  const [editing, setEditing] = useState<string | null>(null);
  const [forms, setForms] = useState<ReadonlyMap<string, Form>>(new Map());
  const [saving, setSaving] = useState<string | null>(null);
  const [pending, setPending] = useState<(Pending & { done: Directory | null }) | null>(null);
  const [landing, setLanding] = useState<Landing | null>(null);
  const [gen, setGen] = useState<GenPrefs>({ kind: GeneratorKind.Password, ...DEFAULT_GENERATOR });
  const refills = useRef(new Refills());
  // Moves on every refusal, so a form still drawn hears of it.
  const [refusals, setRefusals] = useState(0);
  const [prints, setPrints] = useState<ReadonlyMap<string, ShownFingerprint>>(new Map());
  const printsRef = useRef(prints);
  printsRef.current = prints;
  // Each fetch's turn per member: only the latest answer is taken.
  const printTurn = useRef(new Map<string, number>());
  const dirRef = useRef(dir);
  dirRef.current = dir;

  const forget = useCallback(
    (key: string) => {
      refills.current.forget(key);
      setForms((m) => {
        if (!m.has(key)) return m;
        const next = new Map(m);
        next.delete(key);
        return next;
      });
    },
    [],
  );
  // Nothing taken from a field outlives the window.
  useEffect(() => () => refills.current.clear(), []);

  // `> edit` typed into the line, or asked by a button: the document turns
  // into its form, and the line goes back to the item.
  useEffect(() => {
    const check = () => {
      const s = store.get().state;
      if (s.verb !== "edit") return;
      const o = store.object();
      const it = o && dirRef.current.has(o) ? dirRef.current.node(o).item : undefined;
      if (!it || it.deleted) return;
      setEditing(it.id);
      store.settle();
    };
    check();
    return store.subscribe(check);
  }, [store]);
  // An item that left the vault is not edited any more.
  useEffect(() => {
    if (editing && !dir.has(`item:${editing}`)) setEditing(null);
  }, [dir, editing]);

  // A saved edit stops showing its draft once a graph read after the save
  // is drawn: the page then reads what the backend has.
  useEffect(() => {
    if (pending?.done && pending.done !== dir) setPending(null);
  }, [dir, pending]);
  // Stepped onto before the frame is painted: the line the catalogue's new
  // slugs broke is never seen.
  useLayoutEffect(() => {
    if (land(landing, dir, store)) setLanding(null);
  }, [dir, landing, store]);

  const save = useCallback(
    async (key: string, typed: ReadonlyMap<string, string>) => {
      const f = forms.get(key);
      if (!f) throw new Error(`no form "${key}" to save`);
      if (problems(f).length || saving) return;
      const draft = draftOf(fillSecrets(f, typed));
      const refused = () => {
        refills.current.hold(key, typed);
        setRefusals((n) => n + 1);
      };
      const after = dirRef.current;
      if (key.startsWith("edit:")) {
        const itemId = key.slice("edit:".length);
        // Shown at once; taken back if the backend refuses.
        setPending({ itemId, draft: withoutValues(draft), done: null });
        setEditing(null);
        try {
          await writes.update(itemId, draft);
        } catch (e) {
          refused();
          setPending(null);
          setEditing(itemId);
          report(new Error(t("edit.saveFailed", { reason: reason(e) })));
          return;
        }
        forget(key);
        setPending((p) => (p && p.itemId === itemId ? { ...p, done: after } : p));
        setLanding({ id: `item:${itemId}`, after });
        return;
      }
      setSaving(key);
      try {
        const id = await writes.create(draft);
        forget(key);
        setLanding({ id: `item:${id}`, after });
      } catch (e) {
        refused();
        report(new Error(t("edit.createFailed", { reason: reason(e) })));
      } finally {
        setSaving(null);
      }
    },
    [forms, saving, writes, report, forget],
  );

  const cancel = useCallback(
    (key: string) => {
      forget(key);
      if (key.startsWith("edit:")) setEditing(null);
      else if (store.get().state.verb !== null) store.verb(null);
    },
    [forget, store],
  );

  const showFingerprint = useCallback(
    (orgId: string, memberId: string) => {
      const key = printKey(orgId, memberId);
      const turn = (printTurn.current.get(key) ?? 0) + 1;
      printTurn.current.set(key, turn);
      const put = (f: ShownFingerprint) => {
        if (printTurn.current.get(key) !== turn) return;
        setPrints((m) => new Map(m).set(key, f));
      };
      put({ phase: FingerprintPhase.Loading });
      writes.memberFingerprint(orgId, memberId).then(
        (words) => put({ phase: FingerprintPhase.Shown, words }),
        (error: unknown) => put({ phase: FingerprintPhase.Failed, error }),
      );
    },
    [writes],
  );
  const hideFingerprint = useCallback((orgId: string, memberId: string) => {
    const key = printKey(orgId, memberId);
    printTurn.current.set(key, (printTurn.current.get(key) ?? 0) + 1);
    setPrints((m) => {
      if (!m.has(key)) return m;
      const next = new Map(m);
      next.delete(key);
      return next;
    });
  }, []);

  const perform = useCallback(
    (e: Effect): Promise<boolean> | null => {
      if ("org" in e) {
        const op = withShownFingerprint(e.org, (orgId, memberId) => {
          const f = printsRef.current.get(printKey(orgId, memberId));
          return f?.phase === FingerprintPhase.Shown ? f.words : null;
        });
        const after = dirRef.current;
        return runOrgWrite(writes, op).then(
          (id) => {
            setLanding({ id: orgLanding(op, id), after });
            return true;
          },
          (err: unknown) => {
            report(new Error(t("verb.org.failed", { reason: reason(err) })));
            throw err;
          },
        );
      }
      if (!("folder" in e)) return null;
      const op = e.folder;
      const after = dirRef.current;
      return runFolderWrite(writes, op).then(
        (id) => {
          if (op.op === FolderOp.Create) setLanding({ id: `folder:${id!}`, after });
          else if (op.op === FolderOp.Rename) setLanding({ id: `folder:${op.id}`, after });
          else setLanding({ id: "personal", after });
          return true;
        },
        (err: unknown) => {
          report(new Error(t("edit.folderFailed", { reason: reason(err) })));
          throw err;
        },
      );
    },
    [writes, report],
  );

  const api = useMemo<WritesApi>(
    () => ({
      writes,
      editing,
      startEdit: (id) => setEditing(id),
      form: (key) => forms.get(key) ?? null,
      setForm: (key, f) => setForms((m) => new Map(m).set(key, f)),
      refill: (key) => refills.current.take(key),
      refillTurn: (key) => refills.current.turn(key),
      cancel,
      save,
      saving,
      pending: pending && { itemId: pending.itemId, draft: pending.draft },
      perform,
      fingerprint: (orgId, memberId) => prints.get(printKey(orgId, memberId)) ?? null,
      showFingerprint,
      hideFingerprint,
      gen,
      setGen,
    }),
    // `refusals` is read through `refillTurn`: a new one is a new api.
    [writes, editing, forms, cancel, save, saving, pending, perform, prints, showFingerprint, hideFingerprint, gen, refusals],
  );
  return <WritesContext.Provider value={api}>{children}</WritesContext.Provider>;
}

const printKey = (orgId: string, memberId: string) => `${orgId}\0${memberId}`;

/// The fingerprint a preview shows for a member: asked for when the preview
/// shows it, forgotten when it goes, so ↵ can only send words on screen.
export function useMemberFingerprint(target: { orgId: string; memberId: string } | null): ShownFingerprint | null {
  const api = useWrites();
  const orgId = target?.orgId ?? null;
  const memberId = target?.memberId ?? null;
  const show = api?.showFingerprint;
  const hide = api?.hideFingerprint;
  useEffect(() => {
    if (orgId === null || memberId === null || !show || !hide) return;
    show(orgId, memberId);
    return () => hide(orgId, memberId);
  }, [orgId, memberId, show, hide]);
  return api && orgId !== null && memberId !== null ? api.fingerprint(orgId, memberId) : null;
}

/// A draft as the page may show it while it is saved: every typed secret
/// named as kept, its value not held.
function withoutValues(d: ItemDraft): ItemDraft {
  const hide = <T,>(x: T): T => (x && typeof x === "object" && "set" in x ? ({ keep: true } as T) : x);
  return { ...d, notes: hide(d.notes), fields: d.fields.map((f) => ("secret" in f ? { ...f, secret: hide(f.secret) } : f)) };
}
