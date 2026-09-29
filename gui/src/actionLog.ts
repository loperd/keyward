/// The window's side of the log of actions: every command it runs, by name,
/// with how it ended and how long it took — including the ones Tauri refuses
/// before their code is reached, over their arguments. Those leave no trace
/// anywhere else, and a setting that "does not save" looked exactly like that.
///
/// The arguments and the answers are never written: they carry passwords,
/// codes and what the generator made. An error has its quoted parts blanked
/// out before it leaves the window — a parser quotes the value it choked on.

type Entry = { cmd: string; ok: boolean; ms: number; error?: string };

const LOG_CMD = "ui_log";

/// Double-quoted parts blanked out, as the Rust side does.
export function scrub(text: string): string {
  return text.replace(/"[^"]*"?/g, '"…"');
}

let queue: Entry[] = [];
let timer: ReturnType<typeof setTimeout> | null = null;
let send: ((entries: Entry[]) => void) | null = null;

function flush() {
  timer = null;
  if (!send || queue.length === 0) return;
  const batch = queue;
  queue = [];
  send(batch);
}

function record(entry: Entry) {
  queue.push(entry);
  // A failure goes at once: it is what the log is read for, and the window may
  // not live another two seconds.
  if (entry.error) flush();
  else if (!timer) timer = setTimeout(flush, 2000);
}

/// A command run through the log: its name, how it ended and how long it
/// took. The arguments and the answer are not looked at.
export async function logged<T>(cmd: string, run: () => Promise<T>): Promise<T> {
  if (cmd === LOG_CMD) return run();
  const started = performance.now();
  try {
    const out = await run();
    record({ cmd, ok: true, ms: Math.round(performance.now() - started) });
    return out;
  } catch (e) {
    record({ cmd, ok: false, ms: Math.round(performance.now() - started), error: scrub(String(e)) });
    throw e;
  }
}

/// Where the entries go, and the window's own uncaught failures. Called once,
/// before anything is drawn; it must never be the reason the window is not.
export function installActionLog(post: (cmd: string, args: unknown) => Promise<unknown>): void {
  try {
    send = (entries) => void post(LOG_CMD, { entries }).catch(() => {});
    window.addEventListener("error", (e) => record({ cmd: "ui.error", ok: false, ms: 0, error: scrub(String(e.message)) }));
    window.addEventListener("unhandledrejection", (e) =>
      record({ cmd: "ui.rejection", ok: false, ms: 0, error: scrub(String(e.reason)) }),
    );
    window.addEventListener("pagehide", flush);
  } catch {
    // A log that cannot start is no reason for a window that cannot either.
  }
}
