// @vitest-environment happy-dom
// The window's own buttons: drawn where the backend has a window to command,
// each one doing what the system's did, and nothing where it has none.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { App } from "./App";
import { DemoBackend } from "../demo-backend";
import { SessionState } from "../backend";
import { Lang, setLang } from "../i18n";

vi.mock("./tokens", () => ({ tokenPx: () => 320 }));
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const caught: unknown[] = [];
(globalThis as unknown as { reportError: (e: unknown) => void }).reportError = (e) => void caught.push(e);
const flush = () =>
  act(async () => {
    await new Promise((r) => setTimeout(r, 0));
  });

describe("the window's buttons", () => {
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
  // The boot screen fades out over the window, inert, with buttons of its
  // own in the same place: the live ones are the window's.
  const live = (sel: string) => [...host.querySelectorAll<HTMLButtonElement>(sel)].filter((e) => !e.closest("[inert]"));
  const press = (cls: string, init: MouseEventInit = {}) =>
    act(async () => void live(`.strip .light.${cls}`)[0]!.dispatchEvent(new MouseEvent("click", { bubbles: true, ...init })));

  it("close, minimise, go full screen and, with ⌥, zoom", async () => {
    const b = new DemoBackend();
    act(() => root.render(<App backend={b} autoBiometric={false} />));
    await flush();
    await flush();
    expect(live(".strip .light")).toHaveLength(3);
    await press("close");
    await press("minimize");
    await press("fullscreen");
    await press("fullscreen", { altKey: true });
    expect(b.calls.filter((c) => c.startsWith("window:"))).toEqual(["window:close", "window:minimize", "window:fullscreen", "window:zoom"]);
  });

  it("stand in the gate's strip too", async () => {
    const b = new DemoBackend({ start: SessionState.Locked });
    act(() => root.render(<App backend={b} autoBiometric={false} />));
    await flush();
    await flush();
    expect(live(".strip .light")).toHaveLength(3);
  });

  it("are not drawn where there is no window of the app's own", async () => {
    const b = new DemoBackend();
    (b as { window?: unknown }).window = undefined;
    act(() => root.render(<App backend={b} autoBiometric={false} />));
    await flush();
    await flush();
    expect(host.querySelector(".strip")).not.toBeNull();
    expect(host.querySelector(".lights")).toBeNull();
  });
});
