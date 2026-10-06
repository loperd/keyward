// What the window holds of an open vault outside React's state, and lets go
// of when the session closes (a lock, a logout, a lock on idle): the path
// and its history (lines name items and carry search words), the plugins'
// dictionaries, the search patterns, the re-prompt's list, a person's saved
// places when they live in memory. After `close` nothing of the catalogue is
// reachable from here; the App drops its own state (the catalogue, the graph,
// the query) in the same step.
import type { Backend } from "../backend";
import { registerWords, unregisterWords, type Words } from "../i18n";
import type { Catalog } from "../model/types";
import { loadPlaces, memoryPlaceStore, storePlaces, type Place, type PlaceStore } from "../path/places";
import { forgetGlobs, type Query } from "../path/query";
import { PathStore } from "../path/store";
import { Reprompt } from "./reprompt";

export class SessionHold {
  private path: PathStore | null = null;
  private readonly words = new Set<string>();
  private open = false;
  /// The places' store: the app's, or one in memory that goes with the session.
  readonly places: PlaceStore;
  private readonly own: (PlaceStore & { clear(): void }) | null;
  readonly reprompt: Reprompt;

  /// `places`: where a person's places are kept across sessions; none (the
  /// default) keeps them in memory for the session only.
  constructor(backend: Backend, places?: PlaceStore) {
    this.own = places ? null : memoryPlaceStore();
    this.places = places ?? this.own!;
    this.reprompt = new Reprompt(backend.verifyReprompt ? (id, pw) => backend.verifyReprompt!(id, pw) : undefined);
  }

  /// The vault is open with this catalogue. On the step from closed to open
  /// the saved places are read (and returned, with what could not be read);
  /// `null` while it stays open.
  opened(catalog: Catalog, icons: ReadonlySet<string>): { places: Place[]; problems: string[] } | null {
    this.reprompt.setGuarded(catalog.items.filter((i) => i.reprompt).map((i) => i.id));
    if (this.open) return null;
    this.open = true;
    return loadPlaces(this.places, icons);
  }

  get isOpen(): boolean {
    return this.open;
  }

  /// The path over this query: made on the first one, read against each new
  /// graph after that.
  pathFor(query: Query, line: string): PathStore {
    if (!this.path) this.path = new PathStore(query, line);
    else if (this.path.q !== query) this.path.rebase(query, false);
    return this.path;
  }
  /// No graph to draw from: no path either.
  dropPath(): null {
    this.path = null;
    return null;
  }
  get currentPath(): PathStore | null {
    return this.path;
  }

  registerWords(ns: string, words: Words) {
    registerWords(ns, words);
    this.words.add(ns);
  }

  savePlaces(places: Place[]): boolean {
    return storePlaces(this.places, places);
  }

  /// The session closed: everything above goes.
  close() {
    this.open = false;
    this.path = null;
    for (const ns of this.words) unregisterWords(ns);
    this.words.clear();
    forgetGlobs();
    this.reprompt.close();
    this.own?.clear();
  }
}
