// Argon2id off the page's thread: a second or more of memory-hard work would
// otherwise freeze the window (and the idle lock's timers) while it runs.
// One derivation per worker: the page starts it, hands over the password's
// bytes and the salt (transferred, so no copy stays in transit), takes the
// master key back (transferred too) and the worker closes. The inputs are
// wiped here whatever happens; a failure answers with no key, never a
// partial one.
import { zero, type Bytes } from "./bytes";
import { argon2Here, type Argon2Params } from "./argon2";

type Request = { pw: Bytes; salt: Bytes; params: Argon2Params };

const scope = globalThis as unknown as {
  onmessage: ((ev: MessageEvent<Request>) => void) | null;
  postMessage(msg: { mk: Bytes | null }, transfer?: Transferable[]): void;
  close(): void;
};

scope.onmessage = (ev) => {
  const { pw, salt, params } = ev.data;
  void (async () => {
    try {
      const mk = await argon2Here(pw, salt, params);
      scope.postMessage({ mk }, [mk.buffer]);
    } catch {
      scope.postMessage({ mk: null });
    } finally {
      zero(pw, salt);
      scope.close();
    }
  })();
};
