// A refused save puts what was typed back into the secret fields: the fields
// are uncontrolled, the save emptied them, and React may draw them anew or run
// the form's effects twice (StrictMode) before the person looks again.
import { describe, expect, it } from "vitest";
import { FieldRefill, Refills, type RefillTarget } from "./refill";

/// Fields as the form draws them: a value each, emptied as a save reads it.
function fields(ids: string[]) {
  const values = new Map(ids.map((id) => [id, ""]));
  const target = (id: string): RefillTarget | undefined => (values.has(id) ? { set: (v) => void values.set(id, v) } : undefined);
  const take = () => {
    const typed = new Map(values);
    for (const id of values.keys()) values.set(id, "");
    return typed;
  };
  const wipe = () => {
    for (const id of values.keys()) values.set(id, "");
  };
  return { values, target, take, wipe };
}

describe("a refused save's refill", () => {
  it("puts the typed values back into an edit's fields drawn again, and once only from the window", () => {
    const box = new Refills();
    const before = fields(["password", "custom:0"]);
    before.values.set("password", "typed-new-pass");
    before.values.set("custom:0", "typed-hidden");
    const typed = before.take();
    expect([...before.values.values()]).toEqual(["", ""]);
    box.hold("edit:a", typed);
    expect(box.turn("edit:a")).toBe(1);

    // The edit's form is drawn anew: new fields, a new form.
    const after = fields(["password", "custom:0"]);
    const form = new FieldRefill();
    form.apply(box.take("edit:a"), after.target);
    expect(Object.fromEntries(after.values)).toEqual({ password: "typed-new-pass", "custom:0": "typed-hidden" });
    expect(box.take("edit:a")).toBeNull();
  });

  it("fills the fields again when React empties them and runs the form's effect a second time", () => {
    const box = new Refills();
    box.hold("edit:a", new Map([["password", "typed-new-pass"]]));
    const f = fields(["password"]);
    const form = new FieldRefill();
    form.apply(box.take("edit:a"), f.target);
    // StrictMode: the field's own cleanup empties it, then the effect runs
    // again with nothing new from the window.
    f.wipe();
    form.apply(box.take("edit:a"), f.target);
    expect(f.values.get("password")).toBe("typed-new-pass");
  });

  it("reaches a new item's form that stayed drawn: the turn moves", () => {
    const box = new Refills();
    const f = fields(["password"]);
    const form = new FieldRefill();
    form.apply(box.take("new:root"), f.target);
    const turn = box.turn("new:root");
    f.values.set("password", "typed-create-pass");
    box.hold("new:root", f.take());
    expect(box.turn("new:root")).toBe(turn + 1);
    form.apply(box.take("new:root"), f.target);
    expect(f.values.get("password")).toBe("typed-create-pass");
  });

  it("lets go of what came back once a new save takes the fields", () => {
    const box = new Refills();
    box.hold("edit:a", new Map([["password", "typed-new-pass"]]));
    const f = fields(["password"]);
    const form = new FieldRefill();
    form.apply(box.take("edit:a"), f.target);
    f.take();
    form.drop();
    form.apply(null, f.target);
    expect(f.values.get("password")).toBe("");
  });

  it("holds nothing for a save with nothing typed, and nothing for a form that was let go", () => {
    const box = new Refills();
    box.hold("edit:a", new Map());
    expect(box.turn("edit:a")).toBe(0);
    expect(box.take("edit:a")).toBeNull();
    box.hold("edit:b", new Map([["password", "x"]]));
    box.forget("edit:b");
    expect(box.take("edit:b")).toBeNull();
  });

  it("refuses loudly when a field it would fill is not drawn", () => {
    const form = new FieldRefill();
    expect(() => form.apply(new Map([["password", "typed"]]), fields([]).target)).toThrow(/not drawn/);
  });
});
