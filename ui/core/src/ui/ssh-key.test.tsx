// @vitest-environment happy-dom
// An ssh key item's key: its public half and fingerprint follow a new key at
// once — made, pasted or worked out again from the stored one — the save
// sends the daemon's draft by its number, the pasted key does not stay in
// the window, and copying the private key is the danger zone's.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { App } from "./App";
import { DemoBackend, DEMO_PLACES, demoContributions } from "../demo-backend";
import { DemoWrites } from "../demo-writes";
import { DEMO } from "../demo";
import { Lang, setLang } from "../i18n";
import { Directory } from "../path/directory";
import { buildDoc } from "../doc/build";
import { draftOf, formForNew, formFromDetail, problems } from "../edit/draft";
import { ItemKind, SecretField } from "../model/types";
import type { SshKeyDraft, SshKeyFrom } from "../backend";

vi.mock("./tokens", () => ({ tokenPx: () => 320 }));
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const caught: unknown[] = [];
(globalThis as unknown as { reportError: (e: unknown) => void }).reportError = (e) => void caught.push(e);
const flush = () =>
  act(async () => {
    await new Promise((r) => setTimeout(r, 0));
  });

describe("an ssh key's form", () => {
  it("holds the public half and the fingerprint, never the private key, and sends a draft by its number", async () => {
    const d = await new DemoBackend().item("key-prod");
    const f = formFromDetail(d);
    expect(f.ssh).toMatchObject({ fingerprint: expect.stringContaining("SHA256:"), publicKey: expect.stringContaining("ssh-ed25519"), draft: null });
    expect(JSON.stringify(f)).not.toContain("privateKey");
    expect(draftOf(f).sshKey).toBeUndefined();
    expect(draftOf({ ...f, ssh: { ...f.ssh!, draft: "d1" } }).sshKey).toEqual({ draft: "d1" });
  });

  it("asks for a key before a new item is saved", () => {
    const f = { ...formForNew(ItemKind.SshKey, { orgId: null, folderId: null, collectionIds: [] }), name: "k" };
    expect(problems(f)).toContain("edit.needKey");
    expect(problems({ ...f, ssh: { publicKey: "ssh-ed25519 AAAA", fingerprint: "SHA256:x", draft: "d1" } })).toEqual([]);
  });
});

describe("an ssh key's page", () => {
  it("copies the private key from the danger zone only", async () => {
    const dir = new Directory(DEMO, demoContributions(), { places: DEMO_PLACES });
    const detail = await new DemoBackend().item("key-prod");
    const doc = buildDoc({ dir, detail, server: "s", places: DEMO_PLACES }, "item:key-prod");
    const danger = doc.sections.filter((s) => s.danger);
    expect(danger).toHaveLength(1);
    expect(danger[0]!.blocks).toEqual([expect.objectContaining({ danger: expect.objectContaining({ action: expect.objectContaining({ act: { copy: { itemId: "key-prod", field: SecretField.PrivateKey } } }) }) })]);
    const elsewhere = doc.sections.filter((s) => !s.danger).flatMap((s) => s.blocks);
    expect(JSON.stringify(elsewhere)).not.toContain(SecretField.PrivateKey + '"}}');
    const fields = doc.sections.flatMap((s) => s.blocks).flatMap((b) => ("field" in b && "key" in b.field ? [b.field.key] : []));
    expect(fields).toEqual(expect.arrayContaining(["field.fingerprint", "field.publicKey"]));
  });
});

describe("an ssh key in the editor", () => {
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
  const line = "personal › ssh-ключи › id-ed25519-production > edit";
  const button = (words: string) => [...document.querySelectorAll<HTMLButtonElement>("button")].find((b) => b.textContent?.includes(words));
  const shown = () => host.querySelector(".keypub")?.textContent ?? "";

  it("shows a generated key's public half at once, and saves it as the daemon's draft", async () => {
    const b = new DemoBackend();
    act(() => root.render(<App backend={b} writes={new DemoWrites(b)} line={line} autoBiometric={false} />));
    await flush();
    await flush();
    expect(shown()).toContain("ssh-ed25519");
    await act(async () => button("Сгенерировать")!.click());
    await flush();
    expect(b.calls).toContain("ssh-draft:ed25519");
    expect(shown()).toContain("DemoDraft1");
    expect(host.textContent).toContain("DemoDraft1x");
  });

  it("reads a pasted key in a sheet of its own and empties the field", async () => {
    const b = new DemoBackend();
    act(() => root.render(<App backend={b} writes={new DemoWrites(b)} line={line} autoBiometric={false} />));
    await flush();
    await flush();
    await act(async () => button("Вставить свой ключ")!.click());
    const area = document.querySelector<HTMLTextAreaElement>(".keysheet textarea")!;
    expect(area).not.toBeNull();
    area.value = "-----BEGIN OPENSSH PRIVATE KEY-----\nmade-up\n-----END OPENSSH PRIVATE KEY-----";
    await act(async () => button("Прочитать ключ")!.click());
    await flush();
    expect(area.value, "the key leaves the field when it is handed over").toBe("");
    expect(b.calls).toContain("ssh-draft:paste");
    expect(document.querySelector(".keysheet")).toBeNull();
    expect(shown()).toContain("DemoDraft");
  });

  it("works the public half out again from the stored key", async () => {
    const b = new DemoBackend();
    act(() => root.render(<App backend={b} writes={new DemoWrites(b)} line={line} autoBiometric={false} />));
    await flush();
    await flush();
    await act(async () => button("Пересчитать из закрытого")!.click());
    await flush();
    expect(b.calls).toContain("ssh-draft:stored");
    expect(shown()).toContain("DemoDraft");
  });

  it("keeps the editor open while a key is being read, clears its passphrase, and preserves the old key on refusal", async () => {
    const b = new DemoBackend();
    let refuse!: (e: Error) => void;
    const read = vi.spyOn(b, "sshKeyDraft").mockImplementation((_from: SshKeyFrom) => new Promise<SshKeyDraft>((_, reject) => { refuse = reject; }));
    act(() => root.render(<App backend={b} writes={new DemoWrites(b)} line={line} autoBiometric={false} />));
    await flush();
    await flush();
    const previous = shown();
    await act(async () => button("Вставить свой ключ")!.click());
    const area = document.querySelector<HTMLTextAreaElement>(".keysheet textarea")!;
    const pass = document.querySelector<HTMLInputElement>('.keysheet input[type="password"]')!;
    area.value = "private material";
    pass.value = "a passphrase";
    act(() => button("Прочитать ключ")!.click());
    expect(read).toHaveBeenCalledWith({ paste: "private material", passphrase: "a passphrase" });
    expect(area.value).toBe("");
    expect(pass.value).toBe("");
    const escaped = new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true });
    const saved = new KeyboardEvent("keydown", { key: "s", metaKey: true, bubbles: true, cancelable: true });
    act(() => { area.dispatchEvent(escaped); area.dispatchEvent(saved); });
    expect(escaped.defaultPrevented).toBe(true);
    expect(saved.defaultPrevented).toBe(true);
    expect(document.querySelector(".keysheet")).not.toBeNull();
    await act(async () => refuse(new Error("invalid private key")));
    expect(document.querySelector('.keysheet [role="alert"]')?.textContent).toContain("invalid private key");
    expect(shown()).toBe(previous);
    act(() => area.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true })));
    expect(document.querySelector(".keysheet")).toBeNull();
    expect(shown()).toBe(previous);
  });
});
