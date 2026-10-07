// A document, described: what the inspector shows for one object, in a small
// vocabulary the core renders — a hero, sections of fields, relations,
// signal lines, a table of members, a door to a map. The core's own pages and
// a plugin's are written in it alike, so a plugin never brings markup of its
// own and every page keeps the same grid.
import type { Text } from "../i18n";
import type { MapRef } from "../path/query";
import type { Field, Level, Member, SecretRef } from "../model/types";
import { enumParser } from "../model/enum";
import type { SettingKey } from "../settings/rows";

/// What a live block shows.
export enum LiveBlock {
  /// The browser extensions, paired and asking.
  Extensions = "extensions",
  /// The account's profile: email, name, the derivation, the fingerprint.
  Profile = "profile",
}

/// What a skeleton block stands for while its content is on its way.
export enum SkeletonKind {
  /// An item's fields: a label, then a value.
  Fields = "fields",
  /// The members table: a tile, a name and an address, the role, the
  /// status, the second step, the access.
  Members = "members",
}

/// A tile's colour: one of the palette's hues, by name.
export enum Hue {
  Sky = "sky",
  Mint = "mint",
  Amber = "amber",
  Orange = "orange",
  Cyan = "cyan",
  BlueHi = "blue-hi",
  Dim = "dim",
}
export const parseHue = enumParser(Hue, "a hue");

/// What a lead's tile is.
export enum LeadTile {
  Letter = "letter",
  Icon = "icon",
  Avatar = "avatar",
  Plain = "plain",
  Glyph = "glyph",
  Node = "node",
}

/// The lead of a hero or a relation.
export type Lead =
  | { tile: LeadTile.Letter; of: string; hue: Hue }
  | { tile: LeadTile.Icon; icon: string; hue: Hue }
  | { tile: LeadTile.Avatar; of: string; hue: Hue }
  | { tile: LeadTile.Plain; icon: string }
  | { tile: LeadTile.Glyph; level: Level }
  /// The lead a node has in a column: its item tile, avatar or icon.
  | { tile: LeadTile.Node; id: string };

/// What a button does. A verb opens its preview; a map opens the map; `go`
/// steps to a node; `run` commits a line. `none` is a button the demo draws
/// and nothing answers yet.
export type Act =
  | { verb: string }
  | { map: MapRef }
  | { go: string }
  | { run: string }
  | { reveal: true }
  | { copy: SecretRef }
  | { sync: true }
  | { none: true };
export type Action = { icon: string; label: Text; act: Act };

export type MarkSpec = { level: Level; text: Text };

export type Block =
  /// A label and a value; `copy` copies through the backend by the field's
  /// reference.
  | { field: Text; value: Text; mono?: boolean; dim?: boolean; mark?: MarkSpec; faint?: Text; copy?: Act; open?: boolean }
  /// A field of an opened item: a value, or dots until revealed.
  | { secret: Field; itemId: string; verb?: string; tail?: string }
  /// The item's one-time code, counting down.
  | { totp: string; verb?: string }
  /// A line to another place: lead, name, context, a mark on the right edge.
  | { ref: string | null; lead: Lead; title: Text; mono?: boolean; context?: Text; mark?: MarkSpec; perm?: Text; glyph?: MarkSpec; off?: boolean; nest?: boolean; act?: Act }
  /// A finding: its mark in the lead slot, words, a faint reason, one action.
  | { sig: Level; title: Text; mono?: boolean; sub?: Text; action?: { label: Text; act: Act }; go?: Act }
  | { marks: MarkSpec[] }
  | { members: Member[] }
  | { mapdoor: MapRef; title: Text; sub: Text }
  /// Something on its way, in its shape: an item's fields while the item is
  /// read, the members table while the members are; `words` say the wait.
  | { skeleton: SkeletonKind; rows: number; words?: Text }
  /// One of the app's settings as a live control: the window draws it
  /// against the settings it holds and saves a change at once.
  | { setting: SettingKey }
  /// A block the window keeps up to date itself, from the backend.
  | { live: LiveBlock }
  | { para: Text };

export type Section = { title: Text; count?: number | Text; aside?: { label: Text; act: Act; icon?: string }; blocks: Block[] };

export type Hero = {
  lead: Lead;
  title: Text;
  mono?: boolean;
  /// The places it lives in, each a link; then a quiet word of what it is.
  place: string[];
  what?: Text;
  state?: MarkSpec;
  primary?: Action;
  more?: Action[];
};

export type DocSpec = {
  hero: Hero;
  sections: Section[];
  /// A quiet note at the end, with an info icon.
  note?: Text;
  /// The history line: when it changed.
  history?: Text;
  /// A table needs the wider measure.
  wide?: boolean;
};
