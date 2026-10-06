// A map, described: points in lanes and the lines between them. A map is a
// mode of an object (an item's relations, an organisation's access, the SSH
// topology); its model is built from the graph, never drawn by hand, so a
// point on the map is always a step the columns can take.
import type { Text } from "../i18n";
import type { Level, LoudLevel } from "../model/types";
import { enumParser } from "../model/enum";
import type { MarkSpec } from "../doc/spec";

/// A point's shape says its type; the state's mark sits inside it.
export enum Shape {
  Login = "login",
  Card = "card",
  Note = "note",
  Identity = "identity",
  Ssh = "ssh",
  Host = "host",
  Cluster = "cluster",
  Coll = "coll",
  Folder = "folder",
}

export type MapNode = {
  id: string;
  lane: number;
  /// The node the point steps to; `null` for a point that is only a picture.
  nav: string | null;
  shape?: Shape;
  /// Initials, for a person.
  avatar?: string;
  invited?: boolean;
  level: Level;
  label: Text;
  mono?: boolean;
  /// The quiet second line, then its marks. A tight canvas drops the words
  /// and keeps the marks.
  sub: Text;
  marks: MarkSpec[];
  /// The object the map is of.
  anchor?: boolean;
};

/// A line's kind is its weight and dash; colour only repeats a mark.
export enum EdgeKind {
  In = "in",
  Svc = "svc",
  Token = "token",
  Manage = "manage",
  Edit = "edit",
  Read = "read",
  Hidden = "hidden",
  Invite = "invite",
  Route = "route",
  Refused = "refused",
}
export const parseEdgeKind = enumParser(EdgeKind, "a line kind");
export type MapEdge = {
  a: string;
  b: string;
  kind: EdgeKind;
  level?: LoudLevel;
  words: Text;
  /// Its words stand on the line always, not only under the pointer.
  chip?: boolean;
};

export type Finding = { level: Level; text: Text; focus: string };
export type LegendEntry = { kind: EdgeKind; level?: LoudLevel; text: Text };

export type MapModel = {
  nodes: MapNode[];
  edges: MapEdge[];
  lanes: Text[];
  /// The lane spread evenly; the others follow their neighbours.
  pivot: number;
  title: Text;
  place: Text;
  findings: Finding[];
  legend: LegendEntry[];
};

/// A plugin's line from one of its nodes to an item: what an item's relations
/// map draws beyond the vault's own (a cluster takes its token from here).
export type Link = { from: string; to: string; kind: EdgeKind; level?: LoudLevel; words: Text; short: Text; finding?: Text };
