// Marks and tiles: a state's glyph and words, and the lead slot of a row or a
// hero. A state is never said by colour alone; a tile's colour is decoration.
import { createContext, useContext, useEffect, useState } from "react";
import { currentLang, onLang, text, type Lang, type Text } from "../i18n";
import { LEVEL_MARK } from "../model/signals";
import { Level, ItemKind } from "../model/types";
import { Hue, type Lead, LeadTile } from "../doc/spec";
import { type Directory, NodeKind } from "../path/directory";
import type { Query } from "../path/query";
import type { PathStore } from "../path/store";
import type { Backend } from "../backend";
import type { Place } from "../path/places";
import type { Reprompt } from "./reprompt";
import type { Activity } from "./activity";
import type { ToastKind } from "./toasts";
import type { ScreenStore } from "./screen/store";
import { Icon } from "./Icons";
import { Phase } from "./feedback";
import { initials } from "../map/model";

/// Re-renders on a change of language.
export function useLang(): Lang {
  const [l, set] = useState(currentLang());
  useEffect(() => onLang(set), []);
  return l;
}

/// What every part of the window reads: the graph, the line, the store, the
/// backend, the saved places, and the hooks that change what is shown.
export type Core = {
  dir: Directory;
  query: Query;
  store: PathStore;
  backend: Backend;
  places: Place[];
  server: string;
  /// Save the path as it stands as a place.
  savePlace: () => void;
  /// Say that something failed; nothing is swallowed.
  report: (e: unknown) => void;
  /// Ask the page's secret fields to show themselves (the hero's "Open");
  /// an item that asks for the master password again is left out.
  revealAll: () => void;
  revealTick: number;
  /// The re-prompt: every copy, reveal and one-time code of an item marked
  /// `reprompt` goes through `reprompt.confirm(itemId)` first.
  reprompt: Reprompt;
  /// The backend calls in flight (the activity bar, the sync button).
  activity: Activity;
  /// Say that something happened: done, copied, or a word to note.
  toast: (kind: ToastKind, text: string) => void;
  /// What is open of plugins' declared screens, node by node.
  screens: ScreenStore;
};
export const CoreContext = createContext<Core | null>(null);
export function useCore(): Core {
  const c = useContext(CoreContext);
  if (!c) throw new Error("a part of the window was drawn outside <App>");
  return c;
}

export const LEVEL_CLASS: Record<Level, string> = { [Level.Critical]: "kw-m-crit", [Level.Action]: "kw-m-act", [Level.Warning]: "kw-m-warn", [Level.Healthy]: "kw-m-ok", [Level.Unknown]: "kw-m-unk" };
const LEVEL_WORD: Record<Level, Text> = {
  [Level.Critical]: { key: "level.critical" },
  [Level.Action]: { key: "level.action" },
  [Level.Warning]: { key: "level.warning" },
  [Level.Healthy]: { key: "level.healthy" },
  [Level.Unknown]: { key: "level.unknown" },
};
export const isLoudLevel = (l: Level) => l === Level.Critical || l === Level.Action || l === Level.Warning;

const say = (x: Text | string) => (typeof x === "string" ? x : text(x));

/// A glyph and its words.
export function Mark({ level, words }: { level: Level; words?: Text | string }) {
  return (
    <span className={`kw-mk ${LEVEL_CLASS[level]}`}>
      <i>{LEVEL_MARK[level]}</i>
      <span className="kw-w">{say(words ?? LEVEL_WORD[level])}</span>
    </span>
  );
}

/// The glyph alone, its words for the pointer and a screen reader.
export function Glyph({ level, words }: { level: Level; words?: Text | string }) {
  const w = say(words ?? LEVEL_WORD[level]);
  return (
    <span className={`kw-g ${LEVEL_CLASS[level]}`} title={w} aria-label={w}>
      {LEVEL_MARK[level]}
    </span>
  );
}

const HUES: Hue[] = [Hue.Sky, Hue.Mint, Hue.Amber, Hue.Orange, Hue.Cyan, Hue.BlueHi];
/// A name's hue: the same name always gets the same colour.
export function hueOf(s: string): Hue {
  let h = 0;
  for (const c of s) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return HUES[h % HUES.length]!;
}
/// The letter a tile shows for a name.
export const letterOf = (s: string) => (/[A-Za-zА-Яа-яЁё]/.exec(s)?.[0] ?? "·").toUpperCase();

type TileProps = { lead: Lead; xl?: boolean };

/// The lead slot: a tile of a letter, an icon or initials; a plain icon; a
/// glyph. A node's lead is read from the graph, so a row, a spine, a relation
/// and a hero draw the same thing for the same node.
export function Tile({ lead, xl }: TileProps) {
  const { dir } = useCore();
  const cls = (extra: string, hue?: Hue) => `kw-tile${extra}${xl ? " kw-xl" : ""}${hue ? ` kw-hue-${hue}` : ""}`;
  switch (lead.tile) {
    case LeadTile.Letter:
      return <span className={cls("", lead.hue)}>{letterOf(lead.of)}</span>;
    case LeadTile.Icon:
      return (
        <span className={cls("", lead.hue)}>
          <Icon name={lead.icon} />
        </span>
      );
    case LeadTile.Avatar:
      return <span className={cls(" kw-round", lead.hue)}>{initials(lead.of)}</span>;
    case LeadTile.Plain:
      return (
        <span className="kw-tile kw-plain">
          <Icon name={lead.icon} />
        </span>
      );
    case LeadTile.Glyph:
      return <Glyph level={lead.level} />;
    case LeadTile.Node:
      return <Tile lead={nodeLead(dir, lead.id, !!xl)} {...(xl ? { xl } : {})} />;
  }
}

/// How a node leads its row: an item's tile, a member's initials, an
/// organisation's letter, a plain icon for a place.
export function nodeLead(dir: Directory, id: string, xl = false): Lead {
  const n = dir.node(id);
  const name = text(n.name);
  if (n.item) {
    const k = n.item.kind;
    // A key is cyan as a terminal paints it, a note mint; the rest by name.
    if (k === ItemKind.SshKey) return { tile: LeadTile.Icon, icon: n.icon, hue: Hue.Cyan };
    if (k === ItemKind.SecureNote) return { tile: LeadTile.Icon, icon: n.icon, hue: Hue.Mint };
    return k === ItemKind.Card ? { tile: LeadTile.Icon, icon: n.icon, hue: hueOf(name) } : { tile: LeadTile.Letter, of: name, hue: hueOf(name) };
  }
  if (n.member) return { tile: LeadTile.Avatar, of: n.member.name ?? n.member.email, hue: xl ? Hue.Orange : Hue.Dim };
  if (n.kind === NodeKind.Org) return { tile: LeadTile.Letter, of: name, hue: n.hue ?? Hue.Orange };
  if (xl) return { tile: LeadTile.Icon, icon: n.icon, hue: n.hue ?? Hue.Sky };
  return { tile: LeadTile.Plain, icon: n.icon };
}

export function Kbd({ children }: { children: string }) {
  return <kbd className="kw-kbd">{children}</kbd>;
}

/// An icon button with its words in a tooltip. `phase` is its own action's
/// answer: busy draws a spinner in the icon's place and holds the button,
/// done turns the icon into a check for a moment.
export function IconButton({
  icon,
  tip,
  onClick,
  className,
  disabled,
  phase = Phase.Idle,
}: {
  icon: string;
  tip: string;
  onClick?: () => void;
  className?: string;
  disabled?: boolean;
  phase?: Phase;
}) {
  return (
    <button
      type="button"
      className={`kw-btn kw-ico${phase === Phase.Done ? " kw-done" : ""}${className ? " " + className : ""}`}
      data-tip={tip}
      aria-label={tip}
      aria-busy={phase === Phase.Busy || undefined}
      onClick={onClick}
      disabled={disabled || phase === Phase.Busy}
    >
      <BtnIcon icon={icon} phase={phase} />
    </button>
  );
}

/// A button's icon as its action stands: the icon, a spinner while it runs,
/// a check once it is done. The spinner and the check take the icon's box,
/// so nothing beside it moves.
export function BtnIcon({ icon, phase }: { icon: string; phase: Phase }) {
  if (phase === Phase.Busy) return <Spinner />;
  if (phase === Phase.Done) return <Icon name="check" className="kw-morph" />;
  return <Icon name={icon} />;
}

/// A loader the size of an icon: a ring that turns.
export function Spinner() {
  return (
    <svg className="kw-icon kw-spin" viewBox="0 0 16 16" aria-hidden="true">
      <circle cx="8" cy="8" r="5.5" />
    </svg>
  );
}

export { say };
