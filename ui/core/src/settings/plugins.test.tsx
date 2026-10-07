// @vitest-environment happy-dom
// Settings › Plugins: what is installed and what is offered, each a step of
// its own; turning one on is the consent its preview lists; removing is only
// for what was installed from a package; installing goes to the consent of
// what was installed; a publisher is trusted by its key's five words; a
// source must be an address the daemon takes, and new.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { App } from "../ui/App";
import { DemoBackend } from "../demo-backend";
import { DEMO } from "../demo";
import { DemoPlugins } from "../demo-plugins";
import { Lang, setLang, text } from "../i18n";
import { Directory, NodeKind } from "../path/directory";
import { PLUGIN_VERBS } from "../verbs/plugins";
import { PreviewKind } from "../verbs/spec";
import { PluginAdminOp, PluginPermission } from "../plugin/admin";
import { PLUGINS_PAGE, PluginVerb, installedId, offerId } from "./plugins";
import { SettingsPage } from "./pages";

vi.mock("../ui/tokens", () => ({ tokenPx: () => 320 }));

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const caught: unknown[] = [];
(globalThis as unknown as { reportError: (e: unknown) => void }).reportError = (e) => void caught.push(e);
const flush = () =>
  act(async () => {
    await new Promise((r) => setTimeout(r, 0));
  });

function graph(p = new DemoPlugins()) {
  const c = p.catalog();
  return new Directory(DEMO, [], { settings: [SettingsPage.Plugins], plugins: { installed: p.list(), offers: c.offers, stale: c.stale, sources: p.listSources() } });
}
const verb = (id: PluginVerb) => PLUGIN_VERBS.find((v) => v.id === id)!;
const ready = (id: PluginVerb, dir: Directory, obj: string, arg = "") => {
  const p = verb(id).preview!(dir, obj, arg);
  if (p.kind !== PreviewKind.Ready) throw new Error("not ready");
  return p;
};

describe("the Plugins page", () => {
  it("lists what is installed, then what is offered beyond it", () => {
    const dir = graph();
    const ids = dir.kidIds(PLUGINS_PAGE);
    expect(ids.slice(0, 4)).toEqual(["ssh", "kube", "hashicorp", "notes-sync"].map(installedId));
    // An update of something installed is offered; what stands current is not.
    expect(ids.slice(4).map((id) => dir.node(id).kind)).toEqual([NodeKind.PluginOffer, NodeKind.PluginOffer, NodeKind.PluginOffer]);
    expect(text(dir.node(installedId("notes-sync")).why!)).toMatch(/1/);
  });

  it("is refused with nothing known of plugins", () => {
    expect(() => new Directory(DEMO, [], { settings: [SettingsPage.Plugins] })).toThrow(/nothing known of plugins/);
  });
});

describe("the plugins' verbs", () => {
  it("turn one on with its consent: what it asks for, an update's additions marked", () => {
    const dir = graph();
    const n = dir.node(installedId("notes-sync"));
    expect(verb(PluginVerb.Enable).applies(n)).toBe(true);
    expect(verb(PluginVerb.Disable).applies(n)).toBe(false);
    const p = ready(PluginVerb.Enable, dir, n.id);
    expect(p.steps).toHaveLength(3);
    expect(p.steps.at(-1)!.sub).toEqual({ key: "plug.perm.added" });
    expect(p.now?.map((l) => l.title)).toEqual([{ key: "plug.consent.unverified" }, { key: "plug.consent.added", args: { n: 1 } }]);
    expect(p.effect).toEqual({ plugins: { op: PluginAdminOp.Enable, id: "notes-sync" } });
  });

  it("remove only what was installed from a package", () => {
    const dir = graph();
    expect(verb(PluginVerb.Uninstall).applies(dir.node(installedId("kube")))).toBe(false);
    expect(verb(PluginVerb.Uninstall).applies(dir.node(installedId("notes-sync")))).toBe(true);
    expect(ready(PluginVerb.Uninstall, dir, installedId("notes-sync")).danger).toBe(true);
  });

  it("install what can be, and trust a publisher first", () => {
    const p = new DemoPlugins();
    const dir = graph(p);
    const offers = p.catalog().offers;
    const totp = offerId(offers.find((o) => o.id === "totp-export")!);
    const grafana = offerId(offers.find((o) => o.id === "grafana")!);
    expect(verb(PluginVerb.Install).applies(dir.node(totp))).toBe(true);
    expect(verb(PluginVerb.Install).applies(dir.node(grafana))).toBe(false);
    expect(verb(PluginVerb.Trust).applies(dir.node(grafana))).toBe(true);
    const t = ready(PluginVerb.Trust, dir, grafana);
    expect(t.steps[0]!.title).toEqual({ raw: "copper meadow orbit sable willow" });
    expect(t.effect).toEqual({ plugins: { op: PluginAdminOp.Trust, publisher: "dashboards-inc" } });
  });

  it("take a source only as an address the daemon takes, and only once", () => {
    const dir = graph();
    expect(ready(PluginVerb.AddSource, dir, PLUGINS_PAGE, "ftp://x").blocked).toEqual({ key: "plug.address.bad" });
    expect(ready(PluginVerb.AddSource, dir, PLUGINS_PAGE, "https://plugins.keyward.example/index.json").blocked).toEqual({ key: "plug.source.dupe" });
    const ok = ready(PluginVerb.AddSource, dir, PLUGINS_PAGE, "https://mine.example/index.json");
    expect(ok.blocked).toBeUndefined();
    expect(ok.effect).toEqual({ plugins: { op: PluginAdminOp.Sources, set: ["https://plugins.keyward.example/index.json", "https://mine.example/index.json"] } });
    expect(ready(PluginVerb.RemoveSource, dir, PLUGINS_PAGE).blocked).toEqual({ key: "plug.source.pick" });
  });

  it("order what is asked for the same way every time", () => {
    const p = new DemoPlugins();
    const dir = graph(p);
    const steps = ready(PluginVerb.Enable, dir, installedId("hashicorp")).steps.map((s) => s.title);
    expect(steps[0]).toEqual({ key: "plug.perm.entries" });
    expect(steps.at(-1)).toEqual({ key: "plug.perm.network" });
    expect(p.list().find((x) => x.id === "hashicorp")!.permissions).toContain(PluginPermission.Clipboard);
  });
});

describe("the Plugins page in the window", () => {
  let host: HTMLDivElement;
  let root: Root;
  beforeEach(() => {
    setLang(Lang.Ru);
    host = document.createElement("div");
    document.body.appendChild(host);
    root = createRoot(host);
  });
  afterEach(() => {
    expect(caught.map(String)).toEqual([]);
    act(() => root.unmount());
    host.remove();
  });
  const go = () => host.querySelector<HTMLButtonElement>("button[data-confirm]");

  it("turns a plugin on through its consent, and shows what the daemon then says", async () => {
    const b = new DemoBackend();
    act(() => root.render(<App backend={b} line="settings › settings-plugins › plugin-notes-sync > enable" autoBiometric={false} />));
    await flush();
    await flush();
    expect(host.textContent).toContain("Ходить в сеть");
    await act(async () => go()!.click());
    await flush();
    await flush();
    expect(b.calls).toContain("pluginAdmin:enable");
    expect((await b.pluginList()).find((p) => p.id === "notes-sync")?.enabled).toBe(true);
  });

  it("installs from the catalogue, then opens the consent of what it installed", async () => {
    const b = new DemoBackend();
    const lines: string[] = [];
    act(() => root.render(<App backend={b} line="settings › settings-plugins › offer-totp-export > install" onLine={(l) => lines.push(l)} autoBiometric={false} />));
    await flush();
    await flush();
    await act(async () => go()!.click());
    for (let i = 0; i < 4; i++) await flush();
    expect(b.calls).toContain("pluginAdmin:install");
    expect(lines.at(-1)).toMatch(/plugin-totp-export > enable$/);
    expect(host.textContent).toContain("Читать пароли и другие секретные поля");
  });
});
