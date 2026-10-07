// How this account opens on this computer: Touch ID turned on (it takes the
// master password once, to keep it in the keychain behind the sensor) or
// forgotten, a PIN set (the PIN twice and the master password) or cleared.
// They work on the Unlocking page and are offered by its rows. Pure.
import type { Key, Text } from "../i18n";
import { NodeKind, type Node } from "../path/directory";
import type { Verb } from "../path/query";
import { pageId, SettingsPage } from "../settings/pages";
import { Level } from "../model/types";
import { AccountVerb } from "./account-ids";
import { AccountOp, type Effect, type Preview, PreviewKind, type SecretAsk, SecretAskKind } from "./spec";

const k = (key: Key): Text => ({ key });
const UNLOCK = pageId(SettingsPage.Unlock);
const onUnlock = (n: Node | null) => n?.kind === NodeKind.SettingsPage && n.id === UNLOCK;
const example = () => UNLOCK;

/// The shortest PIN the daemon takes.
export const PIN_MIN = 4;

const PASSWORD: SecretAsk = { id: "password", label: k("verb.acct.password"), kind: SecretAskKind.Password };

function preview(op: AccountOp, word: string, opts: { secrets?: SecretAsk[]; danger?: boolean; note?: Key }): Preview {
  const key = (s: string) => `verb.acct.${word}.${s}` as Key;
  return {
    kind: PreviewKind.Ready,
    target: UNLOCK,
    title: k(key("title")),
    lede: k(key("lede")),
    steps: [
      { title: k(key("s1")), sub: k(key("s1sub")) },
      { title: k(key("s2")), sub: k(key("s2sub")) },
    ],
    stays: [{ level: Level.Healthy, title: k("verb.acct.staysPassword"), sub: k("verb.acct.staysPasswordSub") }],
    go: k(key("go")),
    effect: { account: { op, secrets: null } },
    ...(opts.secrets ? { secrets: opts.secrets } : {}),
    ...(opts.danger ? { danger: true } : {}),
    ...(opts.note ? { note: k(opts.note) } : {}),
  };
}

export { AccountVerb };

export const ACCOUNT_VERBS: Verb[] = [
  { id: AccountVerb.TouchIdOn, name: k("verb.acct.touchOn"), icon: "finger", applies: onUnlock, example, preview: () => preview(AccountOp.RememberBiometric, "touchOn", { secrets: [PASSWORD], note: "verb.fingerprint" }) },
  { id: AccountVerb.TouchIdOff, name: k("verb.acct.touchOff"), icon: "finger", applies: onUnlock, example, preview: () => preview(AccountOp.ForgetBiometric, "touchOff", { danger: true }) },
  {
    id: AccountVerb.Pin,
    name: k("verb.acct.pin"),
    icon: "hash",
    applies: onUnlock,
    example,
    preview: () =>
      preview(AccountOp.SetPin, "pin", {
        secrets: [{ id: "pin", label: k("verb.acct.pinNew"), kind: SecretAskKind.Pin, min: PIN_MIN }, { id: "again", label: k("verb.acct.pinAgain"), kind: SecretAskKind.Pin, same: "pin" }, PASSWORD],
      }),
  },
  { id: AccountVerb.PinOff, name: k("verb.acct.pinOff"), icon: "hash", applies: onUnlock, example, preview: () => preview(AccountOp.ClearPin, "pinOff", { danger: true }) },
];

/// What is wrong with what was typed, as a key; `null` when it may go.
export function secretsProblem(asks: SecretAsk[], typed: Readonly<Record<string, string>>): Key | null {
  for (const a of asks) {
    const v = typed[a.id] ?? "";
    if (v === "") return "verb.acct.empty";
    if (a.min !== undefined && [...v].length < a.min) return "verb.acct.pinShort";
    if (a.same !== undefined && v !== typed[a.same]) return "verb.acct.pinMismatch";
  }
  return null;
}

/// The account's change with the typed secrets in it, for the one call it
/// goes into; any other effect as it was.
export function withSecrets(e: Effect, typed: Readonly<Record<string, string>>): Effect {
  if (!("account" in e)) return e;
  return { account: { ...e.account, secrets: typed } };
}
