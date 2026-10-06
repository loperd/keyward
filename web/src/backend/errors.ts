// The web backend's refusals. Every one is a key of the window's dictionary
// (`err.*` in ui/core/src/i18n), so the window says it in the person's
// language and the backend never holds a sentence. Arguments describe a
// shape or a status, never a value: an error ends up on screen and in bug
// reports, and a secret must not ride along.
import type { Key } from "@keyward/core/i18n";

/// Only the dictionary's error keys: a code missing from it is a compile
/// error here, not a raw key on the screen.
export type ErrorCode = Extract<Key, `err.${string}`>;

export class WebError extends Error {
  readonly code: ErrorCode;
  readonly args: Record<string, string | number>;

  constructor(code: ErrorCode, args: Record<string, string | number> = {}) {
    // The message is the code: what reaches a log is the key, which carries
    // nothing but its own name and the shape-only arguments.
    super(code);
    this.name = "WebError";
    this.code = code;
    this.args = args;
  }
}

export const fail = (code: ErrorCode, args?: Record<string, string | number>): never => {
  throw new WebError(code, args);
};

export const isWebError = (e: unknown, code?: ErrorCode): e is WebError =>
  e instanceof WebError && (code === undefined || e.code === code);
