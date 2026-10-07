// The road to a plugin's declared screens: one sealed link per plugin, made
// once and made again when the plugin has forgotten it (the vault was locked
// meanwhile). Every request goes sealed: a screen may carry a log, a manifest,
// a secret field.
import { openLink, Refused, type Link } from "../plugins/link";
import type { Page, Reply } from "./types";

/// What a request on a plugin's link asks for (keyward-ui's `Request`).
enum RequestKind {
  View = "view",
  Places = "places",
  Act = "act",
}

const links = new Map<string, Promise<Link>>();

async function lane<T>(plugin: string, which: "input" | "output", body: Record<string, unknown>): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    let link = links.get(plugin);
    if (!link) {
      link = openLink({ plugin, link: "ui_link", call: "ui" });
      links.set(plugin, link);
    }
    try {
      return await (await link)[which].request<T>(body);
    } catch (e) {
      if (e instanceof Refused) throw new Error(e.message);
      if (attempt > 0) throw e;
      links.delete(plugin);
    }
  }
}

export const view = (plugin: string, route: string) => lane<Page>(plugin, "input", { kind: RequestKind.View, route });
/// What the plugin adds to the new window's path (keyward-ui's `places`); the
/// caller reads the answer, this only carries it.
export const places = (plugin: string) => lane<unknown>(plugin, "input", { kind: RequestKind.Places });
export const act = (plugin: string, op: string, payload?: unknown, form?: Record<string, string>) =>
  lane<Reply>(plugin, "input", { kind: RequestKind.Act, op, payload: payload ?? null, form: form ?? null });
/// A long poll — a stream's output — on the other lane, so that it does not
/// hold the keystrokes behind it.
export const actOut = (plugin: string, op: string, payload?: unknown) =>
  lane<Reply>(plugin, "output", { kind: RequestKind.Act, op, payload: payload ?? null, form: null });
