// The window's motion state: the counter of calls in flight, a button's
// busy → done → idle answer (a copy's check), the toasts, and what moved
// between two drawings of a list.
import { describe, expect, it } from "vitest";
import { Activity, tracked, Busy } from "./activity";
import { DONE_MS, Feedback, type Timers, Outcome } from "./feedback";
import { TOAST_MAX, TOAST_MS, Toasts, ToastKind } from "./toasts";
import { diffRows, snapshotOf, withGone } from "./row-motion";
import { copiedWords } from "./act";
import { setLang, Lang } from "../i18n";
import { SecretField } from "../model/types";

/// Timers moved by hand.
function clock() {
  let now = 0;
  let next = 1;
  const due = new Map<number, { at: number; fn: () => void }>();
  const timers: Timers = {
    set: (fn, ms) => {
      const id = next++;
      due.set(id, { at: now + ms, fn });
      return id;
    },
    clear: (id) => void due.delete(id as number),
  };
  const advance = (ms: number) => {
    now += ms;
    for (const [id, t] of [...due].sort((a, b) => a[1].at - b[1].at)) {
      if (t.at > now) continue;
      due.delete(id);
      t.fn();
    }
  };
  return { timers, advance, pending: () => due.size };
}

const deferred = <T,>() => {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};

describe("the activity counter", () => {
  it("counts calls in flight, by kind and in all, and tells every change", () => {
    const a = new Activity();
    const seen: number[] = [];
    a.subscribe(() => seen.push(a.count()));
    const one = a.begin();
    const two = a.begin(Busy.Sync);
    expect([a.count(), a.count(Busy.Call), a.count(Busy.Sync), a.busy(Busy.Sync)]).toEqual([2, 1, 1, true]);
    two();
    expect(a.busy(Busy.Sync)).toBe(false);
    expect(a.busy()).toBe(true);
    one();
    expect(a.busy()).toBe(false);
    expect(seen).toEqual([1, 2, 1, 0]);
  });

  it("refuses to end a span twice", () => {
    const a = new Activity();
    const end = a.begin();
    end();
    expect(end).toThrow(/ended twice/);
    expect(a.count()).toBe(0);
  });

  it("tracks a call until it settles, either way, and passes its answer and its error on", async () => {
    const a = new Activity();
    const ok = deferred<number>();
    const p = a.track(() => ok.promise);
    expect(a.count()).toBe(1);
    ok.resolve(7);
    await expect(p).resolves.toBe(7);
    expect(a.count()).toBe(0);
    const no = a.track(() => Promise.reject(new Error("refused")));
    expect(a.count()).toBe(1);
    await expect(no).rejects.toThrow("refused");
    expect(a.count()).toBe(0);
    expect(() =>
      a.track(() => {
        throw new Error("before any promise");
      }),
    ).toThrow("before any promise");
    expect(a.count()).toBe(0);
  });

  it("wraps an object's tracked calls, leaves the rest and the absent alone, and keeps `this`", async () => {
    const a = new Activity();
    const gate = deferred<void>();
    class B {
      name = "b";
      async sync() {
        await gate.promise;
        return this.name;
      }
      async copy() {
        return { clearsIn: 30 };
      }
      subscribe() {
        return this.name;
      }
    }
    const b = tracked(new B() as B & { pluginAct?: () => Promise<void> }, a);
    expect(b.pluginAct).toBeUndefined();
    expect(b.subscribe()).toBe("b");
    expect(a.count()).toBe(0);
    const s = b.sync();
    expect(a.busy(Busy.Sync)).toBe(true);
    gate.resolve();
    await expect(s).resolves.toBe("b");
    expect(a.busy()).toBe(false);
    await expect(b.copy()).resolves.toEqual({ clearsIn: 30 });
    expect(b.sync).toBe(b.sync);
  });
});

describe("a button's answer (the copy's check)", () => {
  it("runs busy, shows done for its moment, then stands idle", async () => {
    const c = clock();
    const fb = new Feedback(DONE_MS, c.timers);
    const phases: string[] = [];
    fb.subscribe(() => phases.push(fb.phase()));
    const call = deferred<Outcome>();
    const run = fb.run(() => call.promise);
    expect(fb.phase()).toBe("busy");
    call.resolve(Outcome.Done);
    await expect(run).resolves.toBe(true);
    expect(fb.phase()).toBe("done");
    c.advance(DONE_MS - 1);
    expect(fb.phase()).toBe("done");
    c.advance(1);
    expect(fb.phase()).toBe("idle");
    expect(phases).toEqual(["busy", "done", "idle"]);
  });

  it("holds while busy: a second press runs nothing", async () => {
    const fb = new Feedback(DONE_MS, clock().timers);
    const call = deferred<Outcome>();
    let runs = 0;
    void fb.run(() => {
      runs++;
      return call.promise;
    });
    await expect(fb.run(async () => (runs++, Outcome.Done))).resolves.toBe(false);
    expect(runs).toBe(1);
    call.resolve(Outcome.Done);
  });

  it("says nothing for a step that moved on or a prompt given up, and nothing for a refusal", async () => {
    const c = clock();
    const fb = new Feedback(DONE_MS, c.timers);
    await fb.run(async () => Outcome.None);
    expect(fb.phase()).toBe("idle");
    await fb.run(async () => Outcome.Failed);
    expect(fb.phase()).toBe("idle");
    await expect(fb.run(() => Promise.reject(new Error("lost")))).rejects.toThrow("lost");
    expect(fb.phase()).toBe("idle");
    expect(c.pending()).toBe(0);
  });

  it("starts over when pressed again while done", async () => {
    const c = clock();
    const fb = new Feedback(DONE_MS, c.timers);
    await fb.run(async () => Outcome.Done);
    c.advance(DONE_MS / 2);
    const again = deferred<Outcome>();
    void fb.run(() => again.promise);
    expect(fb.phase()).toBe("busy");
    expect(c.pending()).toBe(0);
    again.resolve(Outcome.Done);
    await again.promise;
    await Promise.resolve();
    expect(fb.phase()).toBe("done");
  });

  it("changes nothing once the button is let go, and drops its pending check", async () => {
    const c = clock();
    const fb = new Feedback(DONE_MS, c.timers);
    const detach = fb.attach();
    await fb.run(async () => Outcome.Done);
    detach();
    expect(fb.phase()).toBe("idle");
    expect(c.pending()).toBe(0);
    expect(() => fb.run(async () => Outcome.Done)).toThrow(/let go/);
    fb.attach();
    await fb.run(async () => Outcome.Done);
    expect(fb.phase()).toBe("done");
  });

  it("says what was copied and when it leaves the clipboard", () => {
    setLang(Lang.Ru);
    expect(copiedWords({ itemId: "aws", field: SecretField.Password }, { clearsIn: 30 })).toBe("Скопировано: Пароль · очистится через 30 с");
    expect(copiedWords({ itemId: "aws", field: SecretField.Custom, name: "Аккаунт" }, { clearsIn: null })).toBe("Скопировано: Аккаунт");
    expect(() => copiedWords({ itemId: "aws", field: SecretField.Password }, { clearsIn: 0 })).toThrow();
    setLang(Lang.En);
    expect(copiedWords({ itemId: "aws", field: SecretField.Totp }, { clearsIn: 45 })).toBe("Copied: Code · clears in 45 s");
    setLang(Lang.Ru);
  });
});

describe("the toasts", () => {
  it("go by themselves after their kind's time, through a way out", () => {
    const c = clock();
    const ts = new Toasts(c.timers);
    const id = ts.push(ToastKind.Copy, "Скопировано");
    c.advance(TOAST_MS.copy - 1);
    expect(ts.all()[0]!.leaving).toBe(false);
    c.advance(1);
    expect(ts.all()[0]!.leaving).toBe(true);
    ts.remove(id);
    expect(ts.all()).toEqual([]);
  });

  it("show the same words once, start their time again, and make room past the most", () => {
    const c = clock();
    const ts = new Toasts(c.timers);
    ts.push(ToastKind.Error, "нет");
    c.advance(TOAST_MS.error - 10);
    ts.push(ToastKind.Error, "нет");
    expect(ts.all()).toHaveLength(1);
    c.advance(20);
    expect(ts.all()[0]!.leaving).toBe(false);
    for (let i = 0; i < TOAST_MAX; i++) ts.push(ToastKind.Ok, `готово ${i}`);
    expect(ts.all().filter((x) => !x.leaving)).toHaveLength(TOAST_MAX);
    expect(ts.all()[0]!.leaving).toBe(true);
    expect(() => ts.push(ToastKind.Ok, "")).toThrow();
  });
});

describe("what moved in a list", () => {
  const snap = (rows: [string, string][]) => snapshotOf(rows, (r) => r[0], (r) => r[1], "ru");
  it("lights what came or changed, and folds what went at its place", () => {
    const d = diffRows(snap([["a", "A"], ["b", "B"], ["c", "C"]]), snap([["a", "A"], ["c", "C2"], ["d", "D"]]));
    expect(d.fresh).toEqual(["c", "d"]);
    expect(d.gone.map((g) => [g.id, g.at])).toEqual([["b", 1]]);
    expect(withGone([1, 3], [{ at: 1, item: 2 }]).map((x) => [x.item, x.gone])).toEqual([[1, false], [2, true], [3, false]]);
  });
  it("refuses a row that stands twice", () => {
    expect(() => snap([["a", "A"], ["a", "A"]])).toThrow(/twice/);
  });
});
