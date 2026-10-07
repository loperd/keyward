// What a button asks for, done: a verb opens its preview, a map opens, a step
// is taken, a line is run, a value is copied through the backend. One place
// for it, so a page, a preview and the map answer a button the same way.
// What it came to is the answer, for the button to show: a copy or a sync
// that finished is "done", a step that moved the line has nothing to add.
import { useCallback } from "react";
import type { Act } from "../doc/spec";
import type { Copied } from "../backend";
import type { Key } from "../i18n";
import { t } from "../i18n";
import { type SecretRef, SecretField } from "../model/types";
import { Outcome } from "./feedback";
import { useCore } from "./marks";
import { ToastKind } from "./toasts";

const FIELD_WORD: Record<Exclude<SecretField, SecretField.Custom>, Key> = {
  [SecretField.Password]: "field.password",
  [SecretField.Username]: "field.username",
  [SecretField.Totp]: "field.totp",
  [SecretField.CardNumber]: "field.cardNumber",
  [SecretField.CardCode]: "field.cardCode",
  [SecretField.Notes]: "field.notes",
  [SecretField.PrivateKey]: "field.privateKey",
};

/// The toast's words for a copy: what went to the clipboard, and when it
/// leaves it.
export function copiedWords(ref: SecretRef, c: Copied): string {
  const what = ref.field === SecretField.Custom ? ref.name : t(FIELD_WORD[ref.field]);
  if (c.clearsIn === null) return t("ui.toast.copied", { what });
  if (!Number.isInteger(c.clearsIn) || c.clearsIn <= 0) throw new Error(`a copy that clears in ${c.clearsIn} s`);
  return t("ui.toast.copiedClears", { what, n: c.clearsIn });
}

export function useAct(): (a: Act) => Promise<Outcome> {
  const { store, backend, report, revealAll, reprompt, toast, screens } = useCore();
  return useCallback(
    async (a: Act): Promise<Outcome> => {
      if ("verb" in a) store.verb(a.verb);
      else if ("map" in a) store.openMap(a.map);
      else if ("go" in a) store.go(a.go);
      else if ("run" in a) store.commit(a.run);
      else if ("screen" in a) screens.open(a.screen.node, a.screen.plugin, a.screen.route);
      else if ("copy" in a) {
        const ref = a.copy;
        try {
          // An item that asks for the master password again copies nothing
          // before it is given.
          if (!(await reprompt.confirm(ref.itemId))) return Outcome.None;
          toast(ToastKind.Copy, copiedWords(ref, await backend.copy(ref)));
          return Outcome.Done;
        } catch (e) {
          report(e);
          return Outcome.Failed;
        }
      } else if ("sync" in a) {
        try {
          await backend.sync();
          return Outcome.Done;
        } catch (e) {
          report(e);
          return Outcome.Failed;
        }
      } else if ("reveal" in a) revealAll();
      // `none` is answered by nothing: the demo draws buttons the backend has
      // no call for yet.
      return Outcome.None;
    },
    [store, backend, report, revealAll, reprompt, toast, screens],
  );
}
