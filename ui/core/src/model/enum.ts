// How a word from outside becomes one of the window's states. Every state,
// kind, step and level the core knows is a string enum whose values are the
// wire's words, so JSON, URLs and tests keep their shapes; a word arrives as
// a plain string (the daemon's JSON, the server's, a plugin's declaration, a
// typed line, the browser's storage) and is turned into a member once, here,
// at the boundary. After that only members are compared. A word that is not
// a member is refused loudly, never read as some default.

/// A word that is no member of the enum it was read as.
export class UnknownEnumValue extends Error {
  constructor(
    readonly what: string,
    readonly value: unknown,
  ) {
    super(`${what} "${String(value)}" is not one the window knows`);
    this.name = "UnknownEnumValue";
  }
}

type StringEnum = Record<string, string>;

/// boundary: whether `raw` is one of the enum's words.
export function isEnumValue<E extends StringEnum>(e: E, raw: unknown): raw is E[keyof E] {
  return typeof raw === "string" && (Object.values(e) as string[]).includes(raw);
}

/// boundary: the one parse function of an enum — the member a word names,
/// or `UnknownEnumValue`, naming `what` was being read.
export function enumParser<E extends StringEnum>(e: E, what: string): (raw: unknown) => E[keyof E] {
  const values = new Set<string>(Object.values(e));
  return (raw) => {
    if (typeof raw === "string" && values.has(raw)) return raw as E[keyof E];
    throw new UnknownEnumValue(what, raw);
  };
}
