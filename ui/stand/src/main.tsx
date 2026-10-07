// The stand: the core's window over the demo backend. The URL keeps the line
// (?q=) and the language (?lang=en); a preset (?p=) opens one of the concept's
// screens, so a picture of the stand can be laid next to a picture of the
// concept; the flags below open the gate instead of the window.
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App, currentLang, onLang, setLang, type Item, type PlaceStore, Lang, SessionState } from "@keyward/core";
import { DEMO, DemoBackend, DemoWrites, DEMO_PLACES, synthetic } from "@keyward/core/demo";

const PRESETS: Record<string, string> = {
  home: "",
  aws: "personal › work › aws-production",
  acme: "acme",
  en: "acme",
  dana: "acme › acme-members › dana-whitfield",
  finance: "acme › acme-collections › finance",
  ssh: "ssh › hosts › db-1",
  critical: "state:critical",
  "critical-step": "state:critical › travel-company-card",
  rotate: "personal › work › aws-production > rotate",
  "map-aws": "personal › work › aws-production map:aws-production",
  "map-acme": "acme › acme-access",
  "map-ssh": "ssh › topology",
  typing: "acme",
};

const qs = new URLSearchParams(location.search);
const preset = qs.get("p");
if (preset !== null && !(preset in PRESETS)) throw new Error(`no preset "${preset}"; there are: ${Object.keys(PRESETS).join(", ")}`);
if (qs.get("lang") === Lang.En || preset === "en") setLang(Lang.En);
const line = qs.get("q") ?? (preset !== null ? PRESETS[preset]! : "");

let current = line;
const keepInUrl = (l: string) => {
  current = l;
  const u = new URL(location.href);
  u.searchParams.delete("p");
  u.searchParams.set("q", l);
  if (currentLang() === Lang.En) u.searchParams.set("lang", Lang.En);
  else u.searchParams.delete("lang");
  history.replaceState(null, "", u);
};
onLang(() => keepInUrl(current));

// The gate on the demo: ?locked=1 opens on unlock, ?signin=1 on the sign-in,
// ?twofactor=1 and ?newdevice=1 add those steps after it, ?choose=1 lets the
// server be chosen as on the desktop, ?pin=1 sets a PIN, ?bio=0 takes Touch ID
// away (the stand never asks for it by itself), ?accounts=1 sets two more
// accounts beside the demo's, ?damaged=1 opens on a session that does not
// read. A password or code "wrong" is refused.
enum DemoFlag {
  Locked = "locked",
  SignIn = "signin",
  TwoFactor = "twofactor",
  NewDevice = "newdevice",
  Choose = "choose",
  Setup = "setup",
  Pin = "pin",
  Bio = "bio",
  Accounts = "accounts",
  Damaged = "damaged",
}
const flag = (k: DemoFlag) => qs.get(k) === "1";
// ?synthetic=10000 serves a vault of that many more items, made up the same
// way each time, beside the demo's own: the stand at a real vault's size.
const many = qs.get("synthetic");
if (many !== null && !/^\d+$/.test(many)) throw new Error(`?synthetic= takes a number of items, not "${many}"`);
// ?slow=1500 makes every read of the demo take that long (the members twice
// as long, in a change of their own): the loading states, to be seen.
const slow = qs.get("slow");
if (slow !== null && !/^\d+$/.test(slow)) throw new Error(`?slow= takes a number of milliseconds, not "${slow}"`);
// ?copies=1 adds two copies of one Apple ID under different names, one with
// another password, a one-time code and a passkey the other lacks: `> merge`,
// to be seen.
const copies = qs.get("copies") === "1";
const appleId = (o: Partial<Item>): Item => ({
  ...DEMO.items.find((i) => i.id === "github")!,
  subtitle: "alex.morgan@icloud.com",
  folderId: null,
  orgId: null,
  collectionIds: [],
  reused: 0,
  reuseGroup: null,
  hasTotp: false,
  passkeys: 0,
  ...o,
});
const COPIES: Item[] = [
  appleId({ id: "second-icloud", name: "second icloud", uris: [] }),
  appleId({ id: "appleid", name: "appleid.icloud.com", uris: ["https://appleid.apple.com"], hasTotp: true, passkeys: 1 }),
];
const backend = new DemoBackend({
  ...(slow !== null ? { slow: Number(slow) } : {}),
  ...(many !== null ? { catalog: synthetic({ items: Number(many), base: DEMO }) } : copies ? { catalog: { ...DEMO, items: [...DEMO.items, ...COPIES] } } : {}),
  start: flag(DemoFlag.Damaged)
    ? SessionState.Damaged
    : flag(DemoFlag.Locked)
      ? SessionState.Locked
      : flag(DemoFlag.Setup)
        ? SessionState.NeedsSetup
        : flag(DemoFlag.SignIn) || flag(DemoFlag.TwoFactor) || flag(DemoFlag.NewDevice)
          ? SessionState.LoggedOut
          : SessionState.Unlocked,
  twoFactor: flag(DemoFlag.TwoFactor),
  newDevice: flag(DemoFlag.NewDevice),
  chooseServer: flag(DemoFlag.Choose),
  accounts: flag(DemoFlag.Accounts),
  pin: flag(DemoFlag.Pin),
  biometric: qs.get(DemoFlag.Bio) !== "0",
});
// The demo's places are kept in the browser's storage, so a saved one
// survives a reload of the stand. Only the stand does this: its vault is made
// up. The real apps keep places in memory (see AppProps.placeStore). Storage
// is reached only inside a call: merely touching it throws where it is
// blocked.
const browserStore: PlaceStore = {
  getItem: (k) => window.localStorage.getItem(k),
  setItem: (k, v) => window.localStorage.setItem(k, v),
};
// The stand's handle for a person trying a refused change by hand.
(window as unknown as { kwDemo: DemoBackend }).kwDemo = backend;
// The demo's writes, in memory: `kwWrites.failNext = "update"` makes the next
// save refuse, to see it taken back.
const writes = new DemoWrites(backend);
(window as unknown as { kwWrites: DemoWrites }).kwWrites = writes;

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App backend={backend} writes={writes} line={line} onLine={keepInUrl} places={DEMO_PLACES} placeStore={browserStore} autoBiometric={false} {...(preset === "typing" ? { startTyping: "state:" } : {})} />
  </StrictMode>,
);
// The idle signal for scripts/ui-check.mjs: set once the first render has
// been committed and painted (two frames after the render was scheduled).
requestAnimationFrame(() => requestAnimationFrame(() => ((window as unknown as { __kwReady: boolean }).__kwReady = true)));
