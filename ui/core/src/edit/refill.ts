// What a refused save took from a form's secret fields, on its way back into
// them. The fields are uncontrolled (ui/secret-input.tsx): a save empties them
// as it reads them, and only this puts the values back.
//
// The window holds what came back from the refusal until the form takes it
// (`Refills`, once). The form keeps what it took for as long as it lives and
// puts it into the fields every time it is asked (`FieldRefill`): React may
// run a form's effects twice (StrictMode), and a field emptied on the way is
// filled again from what the form kept, not from the window, which has let
// it go. A new save drops it; nothing outlives the form.

/// Typed values by slot id.
export type Refill = ReadonlyMap<string, string>;
/// A secret field, as far as a refill writes to it.
export type RefillTarget = { set(value: string): void };

/// The window's side: refusals held per form until the form takes them.
export class Refills {
  private readonly held = new Map<string, Refill>();
  private readonly turns = new Map<string, number>();

  /// A refused save's typed values; nothing typed, nothing held.
  hold(key: string, typed: Refill): void {
    if (!typed.size) return;
    this.held.set(key, typed);
    this.turns.set(key, this.turn(key) + 1);
  }
  /// How many refusals have come back for the form: a form already drawn
  /// takes its refill again when this moves.
  turn(key: string): number {
    return this.turns.get(key) ?? 0;
  }
  /// What came back, handed over once.
  take(key: string): Refill | null {
    const r = this.held.get(key) ?? null;
    this.held.delete(key);
    return r;
  }
  forget(key: string): void {
    this.held.delete(key);
  }
  clear(): void {
    this.held.clear();
  }
}

/// A form's side: what it took, put into the fields drawn now.
export class FieldRefill {
  private kept: Refill | null = null;

  /// Puts `incoming` into the fields, or, when nothing new came, what came
  /// last. A field it names that is not drawn is a broken form: refused
  /// loudly, never skipped.
  apply(incoming: Refill | null, field: (slotId: string) => RefillTarget | undefined): void {
    if (incoming) this.kept = incoming;
    if (!this.kept) return;
    for (const [id, value] of this.kept) {
      const f = field(id);
      if (!f) throw new Error(`the secret field "${id}" a refused save took from is not drawn`);
      f.set(value);
    }
  }
  /// A save took the fields again: what came back before is let go.
  drop(): void {
    this.kept = null;
  }
}
