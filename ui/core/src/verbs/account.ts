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
import { AccountOp, type AccountWrite, type Effect, ExportFormat, type FormGroup, type Preview, PreviewKind, type SecretAsk, SecretAskKind } from "./spec";
import { isEnumValue } from "../model/enum";
import { type Kdf, KdfKind } from "../settings/types";

const k = (key: Key): Text => ({ key });
const UNLOCK = pageId(SettingsPage.Unlock);
const SECURITY = pageId(SettingsPage.Security);
const ACCOUNT = pageId(SettingsPage.Account);
const onAccount = (n: Node | null) => n?.kind === NodeKind.SettingsPage && n.id === ACCOUNT;

/// The shortest new master password, as Bitwarden's clients ask.
export const PASSWORD_MIN = 12;

/// What the server takes for each derivation, and what a new one starts at.
export const KDF_LIMITS = {
  pbkdf2: { iterations: [100_000, 2_000_000] },
  argon2id: { iterations: [1, 10], memoryMib: [15, 1024], parallelism: [1, 16] },
} as const;
export const KDF_DEFAULT: Record<KdfKind, Kdf> = {
  [KdfKind.Pbkdf2]: { kind: KdfKind.Pbkdf2, iterations: 600_000 },
  [KdfKind.Argon2id]: { kind: KdfKind.Argon2id, iterations: 3, memoryMib: 64, parallelism: 4 },
};
const within = (n: number, [lo, hi]: readonly [number, number]) => Number.isInteger(n) && n >= lo && n <= hi;

/// boundary: a derivation as the line names it ("argon2id 3 64 4",
/// "pbkdf2 600000"); the default of its kind for what the line leaves out,
/// `null` for what does not read or is out of the server's bounds.
export function kdfOf(arg: string): Kdf | null {
  const [kind = "", ...nums] = arg.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const n = nums.map(Number);
  if (kind === "" || kind === KdfKind.Argon2id) {
    const d = KDF_DEFAULT[KdfKind.Argon2id];
    if (d.kind !== KdfKind.Argon2id) throw new Error("the default derivation is not argon2id");
    const k: Kdf = { kind: KdfKind.Argon2id, iterations: n[0] ?? d.iterations, memoryMib: n[1] ?? d.memoryMib, parallelism: n[2] ?? d.parallelism };
    const L = KDF_LIMITS.argon2id;
    return nums.length <= 3 && within(k.iterations, L.iterations) && within(k.memoryMib, L.memoryMib) && within(k.parallelism, L.parallelism) ? k : null;
  }
  if (kind === KdfKind.Pbkdf2) {
    const k: Kdf = { kind: KdfKind.Pbkdf2, iterations: n[0] ?? KDF_DEFAULT[KdfKind.Pbkdf2].iterations };
    return nums.length <= 1 && within(k.iterations, KDF_LIMITS.pbkdf2.iterations) ? k : null;
  }
  return null;
}
const kdfArg = (k: Kdf) => (k.kind === KdfKind.Pbkdf2 ? `${k.kind} ${k.iterations}` : `${k.kind} ${k.iterations} ${k.memoryMib} ${k.parallelism}`);

function kdfPreview(arg: string): Preview {
  const kdf = kdfOf(arg);
  const typed = arg.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const kind = typed[0] === KdfKind.Pbkdf2 ? KdfKind.Pbkdf2 : KdfKind.Argon2id;
  const start = KDF_DEFAULT[kind];
  // The numbers as they stand on the line, the kind's defaults where it
  // names none; each field writes its own and keeps the rest.
  const defaults = start.kind === KdfKind.Pbkdf2 ? [start.iterations] : [start.iterations, start.memoryMib, start.parallelism];
  const values = defaults.map((d, i) => typed[i + 1] ?? String(d));
  const labels: Key[] = kind === KdfKind.Pbkdf2 ? ["verb.acct.kdf.iterations"] : ["verb.acct.kdf.iterations", "verb.acct.kdf.memory", "verb.acct.kdf.parallelism"];
  const inputs = labels.map((label, i) => ({
    id: `kdf-${i}`,
    label: k(label),
    text: values[i]!,
    mono: true,
    with: (v: string) => [kind, ...values.map((x, j) => (j === i ? v.trim() || x : x))].join(" "),
  }));
  const choice = (c: KdfKind, label: string) => ({ label: { raw: label }, arg: kdfArg(KDF_DEFAULT[c]), on: kind === c });
  const form: FormGroup[] = [{ inputs: [{ id: "kind", label: k("verb.acct.kdf.kind"), choices: [choice(KdfKind.Argon2id, "Argon2id"), choice(KdfKind.Pbkdf2, "PBKDF2")] }, ...inputs] }];
  const p = preview({ op: AccountOp.ChangeKdf, kdf: kdf ?? start, secrets: null }, "kdf", { secrets: [PASSWORD], target: ACCOUNT, form, stays: ["verb.acct.staysPassword", "verb.acct.staysItems"] });
  if (p.kind !== PreviewKind.Ready) return p;
  return { ...p, now: [{ level: Level.Warning, title: k("verb.acct.relogin"), sub: k("verb.acct.reloginSub") }], ...(kdf === null ? { blocked: k("verb.acct.kdf.bounds") } : {}) };
}

/// The three that take something away for good, or from every device:
/// each with its words and the master password.
function danger(op: AccountOp.Deauthorize | AccountOp.Purge | AccountOp.DeleteAccount, word: string, stays: Key[]): Preview {
  return preview({ op, secrets: null }, word, { secrets: [PASSWORD], target: ACCOUNT, danger: true, stays });
}
const onSecurity = (n: Node | null) => n?.kind === NodeKind.SettingsPage && n.id === SECURITY;

/// boundary: the export's format as the line names it; JSON when it names none.
export function exportFormatOf(arg: string): ExportFormat | null {
  const a = arg.trim().toLowerCase();
  if (a === "") return ExportFormat.Json;
  return isEnumValue(ExportFormat, a) ? a : null;
}

function exportPreview(arg: string): Preview {
  const format = exportFormatOf(arg);
  const choice = (f: ExportFormat, label: string) => ({ label: { raw: label }, arg: f, on: format === f });
  const form: FormGroup[] = [{ inputs: [{ id: "format", label: k("verb.acct.export.format"), choices: [choice(ExportFormat.Json, "JSON"), choice(ExportFormat.Csv, "CSV")] }] }];
  const p = preview({ op: AccountOp.Export, format: format ?? ExportFormat.Json, secrets: null }, "export", {
    secrets: [PASSWORD],
    target: SECURITY,
    form,
    stays: ["verb.acct.export.staysVault"],
  });
  if (p.kind !== PreviewKind.Ready) return p;
  return {
    ...p,
    lede: k(format === ExportFormat.Csv ? "verb.acct.export.ledeCsv" : "verb.acct.export.lede"),
    now: [{ level: Level.Warning, title: k("verb.acct.export.warn"), sub: k("verb.acct.export.warnSub") }],
    ...(format === null ? { blocked: k("verb.acct.export.unknown") } : {}),
  };
}
const onUnlock = (n: Node | null) => n?.kind === NodeKind.SettingsPage && n.id === UNLOCK;
const example = () => UNLOCK;

/// The shortest PIN the daemon takes.
export const PIN_MIN = 4;

const PASSWORD: SecretAsk = { id: "password", label: k("verb.acct.password"), kind: SecretAskKind.Password };

function preview(write: AccountWrite, word: string, opts: { secrets?: SecretAsk[]; danger?: boolean; note?: Key; target?: string; form?: FormGroup[]; stays?: Key[] }): Preview {
  const key = (s: string) => `verb.acct.${word}.${s}` as Key;
  return {
    kind: PreviewKind.Ready,
    target: opts.target ?? UNLOCK,
    title: k(key("title")),
    lede: k(key("lede")),
    steps: [
      { title: k(key("s1")), sub: k(key("s1sub")) },
      { title: k(key("s2")), sub: k(key("s2sub")) },
    ],
    stays: (opts.stays ?? ["verb.acct.staysPassword"]).map((s) => ({ level: Level.Healthy, title: k(s), sub: k(`${s}Sub` as Key) })),
    go: k(key("go")),
    effect: { account: write },
    ...(opts.form ? { form: opts.form } : {}),
    ...(opts.secrets ? { secrets: opts.secrets } : {}),
    ...(opts.danger ? { danger: true } : {}),
    ...(opts.note ? { note: k(opts.note) } : {}),
  };
}

export { AccountVerb };

export const ACCOUNT_VERBS: Verb[] = [
  { id: AccountVerb.TouchIdOn, name: k("verb.acct.touchOn"), icon: "finger", applies: onUnlock, example, preview: () => preview({ op: AccountOp.RememberBiometric, secrets: null }, "touchOn", { secrets: [PASSWORD], note: "verb.fingerprint" }) },
  { id: AccountVerb.TouchIdOff, name: k("verb.acct.touchOff"), icon: "finger", applies: onUnlock, example, preview: () => preview({ op: AccountOp.ForgetBiometric, secrets: null }, "touchOff", { danger: true }) },
  {
    id: AccountVerb.Pin,
    name: k("verb.acct.pin"),
    icon: "hash",
    applies: onUnlock,
    example,
    preview: () =>
      preview({ op: AccountOp.SetPin, secrets: null }, "pin", {
        secrets: [{ id: "pin", label: k("verb.acct.pinNew"), kind: SecretAskKind.Pin, min: PIN_MIN }, { id: "again", label: k("verb.acct.pinAgain"), kind: SecretAskKind.Pin, same: "pin" }, PASSWORD],
      }),
  },
  { id: AccountVerb.Export, name: k("verb.acct.export"), icon: "ext", applies: onSecurity, example: () => SECURITY, preview: (_dir, _obj, arg) => exportPreview(arg) },
  {
    id: AccountVerb.Password,
    name: k("verb.acct.password.name"),
    icon: "key",
    applies: onAccount,
    example: () => ACCOUNT,
    preview: () => {
      const p = preview({ op: AccountOp.ChangePassword, secrets: null }, "password", {
        target: ACCOUNT,
        stays: ["verb.acct.staysItems"],
        secrets: [
          { id: "current", label: k("verb.acct.password.current"), kind: SecretAskKind.Password },
          { id: "new", label: k("verb.acct.password.new"), kind: SecretAskKind.NewPassword, min: PASSWORD_MIN, short: "verb.acct.passwordShort", differs: "current" },
          { id: "again", label: k("verb.acct.password.again"), kind: SecretAskKind.NewPassword, same: "new" },
        ],
      });
      return p.kind === PreviewKind.Ready ? { ...p, now: [{ level: Level.Warning, title: k("verb.acct.relogin"), sub: k("verb.acct.reloginSub") }] } : p;
    },
  },
  { id: AccountVerb.Kdf, name: k("verb.acct.kdf.name"), icon: "tune", applies: onAccount, example: () => ACCOUNT, preview: (_d, _o, arg) => kdfPreview(arg) },
  { id: AccountVerb.SignOutEverywhere, name: k("verb.acct.deauth.name"), icon: "logout", applies: onAccount, example: () => ACCOUNT, preview: () => danger(AccountOp.Deauthorize, "deauth", ["verb.acct.staysItems"]) },
  { id: AccountVerb.Purge, name: k("verb.acct.purge.name"), icon: "trash", applies: onAccount, example: () => ACCOUNT, preview: () => danger(AccountOp.Purge, "purge", ["verb.acct.staysAccount"]) },
  { id: AccountVerb.DeleteAccount, name: k("verb.acct.delete.name"), icon: "trash", applies: onAccount, example: () => ACCOUNT, preview: () => danger(AccountOp.DeleteAccount, "delete", []) },
  { id: AccountVerb.PinOff, name: k("verb.acct.pinOff"), icon: "hash", applies: onUnlock, example, preview: () => preview({ op: AccountOp.ClearPin, secrets: null }, "pinOff", { danger: true }) },
];

/// What is wrong with what was typed, as a key; `null` when it may go.
export function secretsProblem(asks: SecretAsk[], typed: Readonly<Record<string, string>>): Key | null {
  for (const a of asks) {
    const v = typed[a.id] ?? "";
    if (v === "") return "verb.acct.empty";
    if (a.min !== undefined && [...v].length < a.min) return a.short ?? "verb.acct.pinShort";
    if (a.same !== undefined && v !== typed[a.same]) return a.kind === SecretAskKind.Pin ? "verb.acct.pinMismatch" : "verb.acct.passwordMismatch";
    if (a.differs !== undefined && v === typed[a.differs]) return "verb.acct.passwordSame";
  }
  return null;
}

/// The account's change with the typed secrets in it, for the one call it
/// goes into; any other effect as it was.
export function withSecrets(e: Effect, typed: Readonly<Record<string, string>>): Effect {
  if (!("account" in e)) return e;
  return { account: { ...e.account, secrets: typed } };
}
