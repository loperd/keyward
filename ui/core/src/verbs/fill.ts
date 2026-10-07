// Autofill: ⌘⇧L in another app brings the window up on the items for the
// site in front, and `> fill` on one types what the person picks into the
// field that was active there — the login and the password, one of them, the
// one-time code, or a card. Pure; the window carries out the effect.
import type { Key, Text } from "../i18n";
import { NodeKind, type Node } from "../path/directory";
import type { Verb } from "../path/query";
import { ItemKind, Level } from "../model/types";
import { isEnumValue } from "../model/enum";
import { type Preview, PreviewKind } from "./spec";

/// What a fill types.
export enum FillMode {
  Both = "both",
  Username = "username",
  Password = "password",
  Totp = "totp",
  Card = "card",
}

/// What was in front at ⌘⇧L: the app, the site's domain if a browser showed
/// one, and whether the field lies in a form proven to be a login (one field
/// for each, side by side) — only then are both typed at once.
export type FillContext = { app: string; domain: string | null; loginPair: boolean };

export const FILL_VERB = "fill";

const k = (key: Key, args?: Record<string, string>): Text => (args ? { key, args } : { key });
const fillable = (n: Node | null) => n?.kind === NodeKind.Item && !!n.item && !n.item.deleted && (n.item.kind === ItemKind.Login || n.item.kind === ItemKind.Card);

const LABEL: Record<FillMode, Key> = {
  [FillMode.Both]: "fill.both",
  [FillMode.Username]: "fill.username",
  [FillMode.Password]: "fill.password",
  [FillMode.Totp]: "fill.totp",
  [FillMode.Card]: "fill.card",
};

/// What an item offers to type, in the order it is offered.
export function fillModes(n: Node): FillMode[] {
  const it = n.item!;
  if (it.kind === ItemKind.Card) return [FillMode.Card];
  return [FillMode.Both, FillMode.Username, FillMode.Password, ...(it.hasTotp ? [FillMode.Totp] : [])];
}

/// boundary: the mode the line names, the item's first when it names none.
export function fillModeOf(n: Node, arg: string): FillMode | null {
  const a = arg.trim().toLowerCase();
  const modes = fillModes(n);
  if (a === "") return modes[0]!;
  return isEnumValue(FillMode, a) && modes.includes(a) ? a : null;
}

export function fillVerb(ctx: FillContext | null): Verb {
  return {
    id: FILL_VERB,
    name: k("fill.verb"),
    icon: "edit",
    applies: (n) => ctx !== null && fillable(n),
    preview: (dir, obj, arg): Preview => {
      const n = dir.node(obj);
      const mode = fillModeOf(n, arg);
      const into = ctx?.app ?? "";
      return {
        kind: PreviewKind.Ready,
        target: obj,
        title: k("fill.title"),
        lede: k("fill.lede", { app: into }),
        form: [{ inputs: [{ id: "mode", label: k("fill.what"), choices: fillModes(n).map((m) => ({ label: k(LABEL[m]), arg: m, on: m === mode, ...(m === FillMode.Both && !ctx?.loginPair ? { off: k("fill.bothOff") } : {}) })) }] }],
        steps: [
          { title: k("fill.s1"), sub: k("fill.s1sub", { app: into }) },
          { title: k("fill.s2"), sub: k("fill.s2sub") },
        ],
        stays: [{ level: Level.Healthy, title: k("fill.stays"), sub: k("fill.staysSub") }],
        go: k("fill.go"),
        note: k("verb.fingerprint"),
        effect: mode ? { fill: { itemId: n.item!.id, mode } } : { none: true },
        ...(mode === null ? { blocked: k("fill.unknown") } : mode === FillMode.Both && !ctx?.loginPair ? { blocked: k("fill.bothOff") } : {}),
      };
    },
  };
}
