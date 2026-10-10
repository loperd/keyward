import { beforeEach, describe, expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { DemoBackend } from "@keyward/core/demo";
import { draftOf, formFromDetail } from "../../ui/core/src/edit/draft";
import { DaemonWrites } from "./writes";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

describe("an SSH key crosses the desktop's write boundary by its draft", () => {
  const call = vi.mocked(invoke);
  beforeEach(() => call.mockReset());

  async function key() {
    const detail = await new DemoBackend().item("key-prod");
    const form = formFromDetail(detail);
    return { detail, form, draft: draftOf({ ...form, ssh: { publicKey: "ssh-ed25519 new-public", fingerprint: "SHA256:new", draft: "new-key-draft" } }) };
  }

  it("creates with a daemon draft and sends neither private material nor derived fields", async () => {
    const { draft } = await key();
    call.mockResolvedValue("created-key");
    const writes = new DaemonWrites(vi.fn(), vi.fn());
    await expect(writes.create(draft)).resolves.toBe("created-key");
    expect(call).toHaveBeenCalledWith("item_create", expect.objectContaining({
      kind: 5,
      edit: expect.objectContaining({ ssh_key: { source: "draft", id: "new-key-draft" } }),
    }));
    const payload = JSON.stringify(call.mock.calls);
    expect(payload).not.toContain("private_key");
    expect(payload).not.toContain("new-public");
    expect(payload).not.toContain("SHA256:new");
  });

  it("replaces an existing key with the daemon draft", async () => {
    const { detail, form, draft } = await key();
    call.mockImplementation(async (command) => {
      if (command === "item_detail") return {
        name: detail.item.name,
        favorite: detail.item.favorite,
        reprompt: detail.item.reprompt,
        uris: form.uris,
        fields: detail.fields,
        custom: [],
      };
      if (command === "vault_items") return { items: [{
        id: detail.item.id, kind: detail.item.kind, org_id: detail.item.orgId,
        folder_id: detail.item.folderId, collection_ids: detail.item.collectionIds,
        tags: draft.tags,
      }] };
      return { state: { state: "pending" } };
    });
    const writes = new DaemonWrites(vi.fn(), vi.fn());
    await writes.update(detail.item.id, draft);
    expect(call).toHaveBeenCalledWith("update_item", expect.objectContaining({
      entryId: detail.item.id,
      edit: expect.objectContaining({ ssh_key: { source: "draft", id: "new-key-draft" } }),
    }));
    expect(JSON.stringify(call.mock.calls)).not.toContain("private_key");
  });

  it("refuses to create an SSH item without a key", async () => {
    const { form } = await key();
    const writes = new DaemonWrites(vi.fn(), vi.fn());
    await expect(writes.create(draftOf(form))).rejects.toThrow("an ssh key item is made from a key");
    expect(call).not.toHaveBeenCalled();
  });
});
