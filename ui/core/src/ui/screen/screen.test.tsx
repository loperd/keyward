// @vitest-environment happy-dom
// A plugin's declared screen in the window: a place's page offers it, the
// screen stands in the page's stead with its tables, a row opens a drawer,
// Escape closes the topmost first, a dialogue's form is sent once — its
// secret read from the field and emptied, never kept — and the screen is
// closed back to the page.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { App } from "../App";
import { DemoBackend } from "../../demo-backend";
import { Lang, setLang } from "../../i18n";

vi.mock("../tokens", () => ({ tokenPx: () => 320 }));

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const caught: unknown[] = [];
(globalThis as unknown as { reportError: (e: unknown) => void }).reportError = (e) => void caught.push(e);
const flush = () =>
  act(async () => {
    await new Promise((r) => setTimeout(r, 0));
  });

describe("a plugin's screen", () => {
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
    setLang(Lang.Ru);
  });

  const button = (words: string) => [...host.querySelectorAll<HTMLButtonElement>("button")].find((b) => b.textContent?.trim() === words || b.getAttribute("aria-label") === words);
  const press = async (el: Element | null | undefined) => {
    if (!el) throw new Error("nothing to press");
    await act(async () => (el as HTMLElement).click());
    await flush();
    await flush();
  };
  const key = async (k: string) => {
    await act(async () => document.dispatchEvent(new KeyboardEvent("keydown", { key: k, bubbles: true })));
    await flush();
  };

  async function openCluster(b: DemoBackend) {
    act(() => root.render(<App backend={b} line="kubernetes › prod-eu-1" autoBiometric={false} />));
    await flush();
    await flush();
    expect(host.querySelector(".h1")?.textContent).toBe("prod-eu-1");
    await press(button("Открыть"));
  }

  it("opens from its place's page and draws its table", async () => {
    const b = new DemoBackend();
    await openCluster(b);
    expect(b.calls).toContain("pluginView:cluster/prod-eu-1");
    expect(b.calls).toContain("pluginRun:table");
    const rows = [...host.querySelectorAll(".stable tbody tr")].map((r) => r.querySelector("td")?.textContent);
    expect(rows).toContain("worker-5c8d7f9b8-qq4lp");
    // The facets filter in the window: one namespace leaves its pods.
    const ns = host.querySelector<HTMLSelectElement>('.ssel select[aria-label="Пространство"]')!;
    await act(async () => {
      ns.value = "data";
      ns.dispatchEvent(new Event("change", { bubbles: true }));
    });
    expect(host.querySelectorAll(".stable tbody tr")).toHaveLength(2);
    expect(host.querySelector(".sshown")?.textContent).toBe("2 из 5");
  });

  it("opens a row's drawer, and Escape closes it, then the screen", async () => {
    const b = new DemoBackend();
    await openCluster(b);
    await press(host.querySelector(".stable tbody tr"));
    const drawer = host.querySelector(".drawer");
    expect(drawer?.querySelector(".ohead-t b")?.textContent).toMatch(/^api-|^postgres|^worker|^migrate/);
    expect(b.calls).toContain("pluginRun:logs_node");
    expect(drawer?.querySelector(".spre")?.textContent).toContain("listening on :8080");
    await key("Escape");
    expect(host.querySelector(".drawer")).toBeNull();
    expect(host.querySelector(".stable")).not.toBeNull();
    await key("Escape");
    // The sheet that was let go fades out where it stood (a ghost, emptied).
    expect(host.querySelector(".doc:not(.ghost) .stable")).toBeNull();
    expect(button("Открыть")).toBeTruthy();
  });

  it("sends a dialogue's form once, its secret read from the field and kept nowhere", async () => {
    const b = new DemoBackend();
    await openCluster(b);
    await press(button("Создать"));
    const dialog = host.querySelector(".dialog")!;
    expect(dialog).not.toBeNull();
    const name = dialog.querySelector<HTMLInputElement>('input[aria-label="Имя"]')!;
    const token = dialog.querySelector<HTMLInputElement>('input[aria-label="Токен"]')!;
    expect(token.type).toBe("password");
    await act(async () => {
      name.value = "cache";
      token.value = "s3cr3t-token";
      token.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await press([...dialog.querySelectorAll<HTMLButtonElement>("button[type=submit]")][0]);
    expect(b.calls).toContain("pluginRun:create_object:name,ns,replicas,token");
    expect(host.querySelector(".dialog")).toBeNull();
    expect(document.body.textContent).toContain("cache создан");
    expect(host.innerHTML).not.toContain("s3cr3t-token");
    expect(b.calls.join("\n")).not.toContain("s3cr3t-token");
  });

  it("asks a row's delete twice and a drawer's danger zone for the name", async () => {
    const b = new DemoBackend();
    await openCluster(b);
    const del = host.querySelector<HTMLButtonElement>('.stable tbody tr .sacts button[aria-label="Удалить"]')!;
    await press(del);
    expect(b.calls).not.toContain("pluginRun:delete_object");
    expect(del.getAttribute("aria-label")).toBe("Нажмите ещё раз");
    await press(del);
    expect(b.calls).toContain("pluginRun:delete_object");

    await press(host.querySelector(".stable tbody tr"));
    const zone = host.querySelector(".drawer .sdanger")!;
    const go = zone.querySelector<HTMLButtonElement>("button.danger")!;
    expect(go.disabled).toBe(true);
    const typed = zone.querySelector<HTMLInputElement>("input")!;
    await act(async () => {
      const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
      set.call(typed, typed.placeholder);
      typed.dispatchEvent(new Event("input", { bubbles: true }));
    });
    expect(go.disabled).toBe(false);
  });
});
