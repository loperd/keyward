// The window's icons: one 16px set, drawn on a 16-unit grid with one stroke,
// so an icon reads the same in a crumb, a row, a menu and a hero. The paths
// are constants of this file, never data, so they are set as markup.
import { Shape } from "../map/types";

const PATHS = {
  vault: '<rect x="2.5" y="3" width="11" height="10" rx="1.5"/><circle cx="8" cy="8" r="2"/><path d="M8 6v-.5M4.5 13v1M11.5 13v1"/>',
  person: '<circle cx="8" cy="5.5" r="2.5"/><path d="M3 13.5c.8-2.6 2.8-3.8 5-3.8s4.2 1.2 5 3.8"/>',
  org: '<path d="M3 13.5V3.5h6v10M9 6.5h4v7M2 13.5h12M5 6h2M5 8.5h2M5 11h2"/>',
  folder: '<path d="M2 4.5c0-.6.4-1 1-1h3l1.5 1.5H13c.6 0 1 .4 1 1V12c0 .6-.4 1-1 1H3c-.6 0-1-.4-1-1z"/>',
  stack: '<path d="M2.5 6L8 3l5.5 3L8 9z"/><path d="M2.5 9L8 12l5.5-3"/>',
  people: '<circle cx="6" cy="6" r="2.2"/><path d="M2 13c.6-2.2 2.1-3.2 4-3.2s3.4 1 4 3.2"/><path d="M10.5 4a2.2 2.2 0 0 1 0 4.2M11.5 9.9c1.3.4 2.1 1.4 2.5 3.1"/>',
  policy: '<path d="M4 2.5h8v11H4z"/><path d="M6 6h4M6 8.5h4M6 11h2"/>',
  pulse: '<path d="M2 8h2.5L6 4l3 8 1.5-4H14"/>',
  terminal: '<rect x="2" y="3" width="12" height="10" rx="1.5"/><path d="M5 6.5l2 1.5-2 1.5M8.5 10h2.5"/>',
  cube: '<path d="M8 2l5.5 3v6L8 14l-5.5-3V5z"/><path d="M2.5 5L8 8l5.5-3M8 8v6"/>',
  server: '<rect x="2.5" y="2.5" width="11" height="4.5" rx="1"/><rect x="2.5" y="9" width="11" height="4.5" rx="1"/><path d="M5 4.75h0M5 11.25h0"/>',
  login: '<circle cx="8" cy="8" r="5.5"/><path d="M2.5 8h11M8 2.5c1.6 1.6 2.4 3.4 2.4 5.5S9.6 11.9 8 13.5c-1.6-1.6-2.4-3.4-2.4-5.5S6.4 4.1 8 2.5"/>',
  card: '<rect x="2" y="3.5" width="12" height="9" rx="1.5"/><path d="M2 6.5h12M4.5 10h2"/>',
  note: '<path d="M4 2.5h5.5L12 5v8.5H4z"/><path d="M9.5 2.5V5H12M6 8h4M6 10.5h4"/>',
  identity: '<rect x="2" y="3.5" width="12" height="9" rx="1.5"/><circle cx="6" cy="7.2" r="1.4"/><path d="M4 10.8c.4-1 1.1-1.5 2-1.5s1.6.5 2 1.5M9.5 7h2.5M9.5 9.5h2.5"/>',
  key: '<circle cx="5.5" cy="10.5" r="2.5"/><path d="M7.3 8.7L13 3M11 5l1.5 1.5M9.5 6.5L11 8"/>',
  chev: '<path d="M6 4l4 4-4 4"/>',
  back: '<path d="M10 3.5L5.5 8l4.5 4.5"/>',
  fwd: '<path d="M6 3.5l4.5 4.5L6 12.5"/>',
  search: '<circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5L13.5 13.5"/>',
  filter: '<path d="M2.5 3.5h11L9.25 8.5v4l-2.5 1.25V8.5z"/>',
  lock: '<rect x="3.5" y="7" width="9" height="6.5" rx="1.5"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"/>',
  copy: '<rect x="5.5" y="5.5" width="8" height="8" rx="1.5"/><path d="M10.5 5.5V3.5c0-.6-.4-1-1-1h-6c-.6 0-1 .4-1 1v6c0 .6.4 1 1 1h2"/>',
  ext: '<path d="M9 2.5h4.5V7M13.5 2.5L8 8M11.5 9.5v3c0 .6-.4 1-1 1h-7c-.6 0-1-.4-1-1v-7c0-.6.4-1 1-1h3"/>',
  moon: '<path d="M13 9.5A5.5 5.5 0 0 1 6.5 3a5.5 5.5 0 1 0 6.5 6.5z"/>',
  sun: '<circle cx="8" cy="8" r="2.8"/><path d="M8 1.5v1.5M8 13v1.5M1.5 8H3M13 8h1.5M3.4 3.4l1 1M11.6 11.6l1 1M3.4 12.6l1-1M11.6 4.4l1-1"/>',
  edit: '<path d="M10.5 2.5l3 3L6 13H3v-3z"/>',
  more: '<path d="M4 8h0M8 8h0M12 8h0" stroke-width="2.2"/>',
  eye: '<path d="M1.5 8S4 3.5 8 3.5 14.5 8 14.5 8 12 12.5 8 12.5 1.5 8 1.5 8z"/><circle cx="8" cy="8" r="2"/>',
  check: '<path d="M3.5 8.5l3 3 6-7"/>',
  refresh: '<path d="M13 8a5 5 0 1 1-1.5-3.6M13 2.5v2.5h-2.5"/>',
  plus: '<path d="M8 3v10M3 8h10"/>',
  logout: '<path d="M6.5 13.5h-3c-.6 0-1-.4-1-1v-9c0-.6.4-1 1-1h3M10.5 11l3-3-3-3M13.5 8H6"/>',
  undo: '<path d="M5.5 3.5L2.5 6.5l3 3"/><path d="M2.5 6.5H10a3.5 3.5 0 0 1 0 7H7"/>',
  dice: '<rect x="2.5" y="2.5" width="11" height="11" rx="2.5"/><path d="M5.5 5.5h0M10.5 5.5h0M8 8h0M5.5 10.5h0M10.5 10.5h0" stroke-width="2"/>',
  tune: '<path d="M2.5 4.5h6M11.5 4.5h2M2.5 11.5h2M7.5 11.5h6"/><circle cx="10" cy="4.5" r="1.5"/><circle cx="6" cy="11.5" r="1.5"/>',
  mail: '<rect x="2" y="3.5" width="12" height="9" rx="1.5"/><path d="M2.5 4.5L8 9l5.5-4.5"/>',
  hash: '<path d="M6 2.5L5 13.5M11 2.5l-1 11M2.5 6h11M2 10h11"/>',
  clock: '<circle cx="8" cy="8" r="5.5"/><path d="M8 5v3l2 1.5"/>',
  info: '<circle cx="8" cy="8" r="5.5"/><path d="M8 7.5v3.5M8 5h0"/>',
  user2: '<circle cx="8" cy="5.5" r="2.5"/><path d="M3 13.5c.8-2.6 2.8-3.8 5-3.8s4.2 1.2 5 3.8"/><path d="M12 3v3M10.5 4.5h3"/>',
  map: '<path d="M1.5 3.5L5.5 2l5 1.5 4-1.5v10.5l-4 1.5-5-1.5-4 1.5z"/><path d="M5.5 2v10.5M10.5 3.5V14"/>',
  close: '<path d="M4 4l8 8M12 4l-8 8"/>',
  verb: '<path d="M3.5 4l4 4-4 4M9 12h4"/>',
  mark: '<path d="M4.5 2.5h7v11L8 11l-3.5 2.5z"/>',
  markOn: '<path d="M4.5 2.5h7v11L8 11l-3.5 2.5z" fill="currentColor"/>',
  finger: '<path d="M5 13c-.8-1.4-1.2-3-1.2-4.7a4.2 4.2 0 0 1 8.4 0v.6M8 8.3c0 2 .5 3.7 1.4 5.2M6 8.4c0-1.1.9-2 2-2s2 .9 2 2c0 1.6.3 2.9.9 4"/>',
  lang: '<circle cx="8" cy="8" r="5.5"/><path d="M2.5 8h11M8 2.5c1.6 1.6 2.4 3.4 2.4 5.5S9.6 11.9 8 13.5c-1.6-1.6-2.4-3.4-2.4-5.5S6.4 4.1 8 2.5"/>',
  trash: '<path d="M3 4.5h10M6.5 4.5V3h3v1.5M4.5 4.5l.6 8.5c0 .6.4 1 1 1h3.8c.6 0 1-.4 1-1l.6-8.5"/>',
  merge: '<path d="M3.5 2.5v2c0 2.2 2 3.5 4.5 4.5 2.5-1 4.5-2.3 4.5-4.5v-2M8 9v4.5M6 11.5l2 2 2-2"/>',
  state: '<circle cx="8" cy="8" r="5.5"/><path d="M8 5v3.5"/><path d="M8 11h0"/>',
} as const;
export type IconName = keyof typeof PATHS;
export const ICONS: ReadonlySet<string> = new Set(Object.keys(PATHS));

export function isIcon(name: string): name is IconName {
  return ICONS.has(name);
}

/// An icon by name. A name the set does not have is an error, not a blank.
export function Icon({ name, className }: { name: string; className?: string }) {
  if (!isIcon(name)) throw new Error(`no icon "${name}"`);
  return <svg className={`kw-icon${className ? " " + className : ""}`} viewBox="0 0 16 16" aria-hidden="true" dangerouslySetInnerHTML={{ __html: PATHS[name] }} />;
}

/// A map point's outline by type; the state's mark sits inside it.
const SHAPES: Record<Shape, string> = {
  [Shape.Login]: '<circle cx="8" cy="8" r="6.75"/>',
  [Shape.Card]: '<rect x="1" y="2.5" width="14" height="11" rx="2.5"/>',
  [Shape.Note]: '<path d="M2.5 1.25h7.25l3.75 3.75v9.75h-11z"/>',
  [Shape.Identity]: '<path d="M8 .9 15.1 8 8 15.1.9 8z"/>',
  [Shape.Ssh]: '<path d="m8 .9 6.4 3.6v7L8 15.1l-6.4-3.6v-7z"/>',
  [Shape.Host]: '<rect x="1.25" y="1.25" width="13.5" height="13.5" rx="3"/>',
  [Shape.Cluster]: '<path d="M5 1.25h6L14.75 5v6L11 14.75H5L1.25 11V5z"/>',
  [Shape.Coll]: '<path d="M1.25 4.5h13.5v10.25H1.25z"/><path d="M3.5 1.25h9"/>',
  [Shape.Folder]: '<path d="M1.25 3.5c0-.6.4-1 1-1h4l1.5 1.5h6c.6 0 1 .4 1 1v8.25c0 .6-.4 1-1 1H2.25c-.6 0-1-.4-1-1z"/>',
};
export function ShapeSvg({ shape }: { shape: Shape }) {
  return <svg viewBox="0 0 16 16" aria-hidden="true" dangerouslySetInnerHTML={{ __html: SHAPES[shape] }} />;
}
