import type { Terminal } from "@xterm/xterm";
import { openLink, Refused, unb64, bytesToB64, type Link } from "./link";
import type { Destination } from "./terminalState";
import type { TermInfo, TermState } from "./types";

/// How long a read waits for output before it asks again.
const READ_WAIT_MS = 15000;

/// How many times a broken link is made anew before the tab gives up.
const RELINKS = 3;

type Events = {
  onInfo: (info: TermInfo) => void;
  onState: (state: TermState) => void;
  /// The link broke and could not be made again: the terminal no longer hears
  /// the shell. A key for `tError`.
  onBroken: (error: string) => void;
};

/// One tab's conversation with its shell: the link, the output it reads and
/// the keystrokes it sends.
///
/// Keystrokes that come while the last ones are on their way are gathered and
/// go together: typing faster than a round trip costs no order and no extra
/// requests. Nothing is typed into a shell that is not open.
export class Controller {
  private link: Link | null = null;
  private session: string | null;
  private cursor = 0;
  private version = 0;
  private state: TermState = { kind: "connecting" };
  private stopped = false;
  private pending: Uint8Array[] = [];
  private writing = false;
  private resizeTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly encoder = new TextEncoder();

  constructor(
    private readonly term: Terminal,
    session: string | undefined,
    private readonly destination: Destination | undefined,
    private readonly events: Events,
  ) {
    this.session = session ?? null;
  }

  async start(): Promise<void> {
    try {
      this.link = await openLink();
      if (this.session) {
        const r = await this.link.input.request<{ session: TermInfo; state: TermState }>({ op: "attach", session: this.session });
        this.events.onInfo(r.session);
        this.setState(r.state);
      } else if (this.destination) {
        const r = await this.link.input.request<{ session: TermInfo; state: TermState }>({
          op: "open",
          target: this.destination,
          cols: this.term.cols,
          rows: this.term.rows,
        });
        this.session = r.session.id;
        this.events.onInfo(r.session);
        this.setState(r.state);
      }
    } catch (e) {
      // A refusal is the plugin's word about this shell; the tab shows it as
      // an ended session.
      if (e instanceof Refused) this.setState({ kind: "closed", error: e.message, exit: null });
      else this.events.onBroken(String(e));
      return;
    }
    this.term.onData((d) => this.type(this.encoder.encode(d)));
    this.term.onBinary((d) => this.type(Uint8Array.from(d, (c) => c.charCodeAt(0) & 0xff)));
    this.term.onResize(({ cols, rows }) => this.resized(cols, rows));
    void this.readLoop();
  }

  stop() {
    this.stopped = true;
    for (const chunk of this.pending) chunk.fill(0);
    this.pending = [];
    if (this.resizeTimer) clearTimeout(this.resizeTimer);
  }

  private setState(state: TermState) {
    const wasOpen = this.state.kind === "open";
    this.state = state;
    this.events.onState(state);
    // The window may have changed size while the shell was coming up.
    if (!wasOpen && state.kind === "open") this.resized(this.term.cols, this.term.rows);
  }

  private async readLoop() {
    let failures = 0;
    while (!this.stopped && this.state.kind !== "closed") {
      try {
        const r = await this.link!.output.request<{ data: string; cursor: number; dropped: boolean; state: TermState; version: number }>({
          op: "read",
          cursor: this.cursor,
          version: this.version,
          wait_ms: READ_WAIT_MS,
        });
        failures = 0;
        if (this.stopped) return;
        if (r.dropped) this.term.write("\r\n\x1b[2m…\x1b[0m\r\n");
        if (r.data) {
          const bytes = unb64(r.data);
          this.term.write(bytes);
        }
        this.cursor = r.cursor;
        if (r.version !== this.version) {
          this.version = r.version;
          this.setState(r.state);
        }
      } catch (e) {
        if (this.stopped) return;
        if (e instanceof Refused) {
          this.setState({ kind: "closed", error: e.message, exit: null });
          return;
        }
        failures += 1;
        if (failures > RELINKS || !(await this.mend())) {
          this.events.onBroken(String(e));
          return;
        }
      }
    }
  }

  private mending: Promise<boolean> | null = null;

  /// One relink at a time, whichever lane noticed the break first.
  private mend(): Promise<boolean> {
    this.mending ??= this.relink().finally(() => {
      this.mending = null;
    });
    return this.mending;
  }

  /// Makes the link anew and re-attaches: a lost answer leaves a lane out of
  /// step, and a new exchange is the only honest way back.
  private async relink(): Promise<boolean> {
    if (!this.session) return false;
    try {
      await new Promise((done) => setTimeout(done, 400));
      const link = await openLink();
      const r = await link.input.request<{ session: TermInfo; state: TermState }>({ op: "attach", session: this.session });
      this.link = link;
      this.setState(r.state);
      return true;
    } catch {
      return false;
    }
  }

  private type(bytes: Uint8Array) {
    if (this.state.kind !== "open" || this.stopped) {
      bytes.fill(0);
      return;
    }
    this.pending.push(bytes);
    if (!this.writing) void this.flush();
  }

  private async flush() {
    this.writing = true;
    try {
      while (this.pending.length && !this.stopped) {
        const chunks = this.pending;
        this.pending = [];
        const size = chunks.reduce((n, c) => n + c.length, 0);
        const all = new Uint8Array(size);
        let at = 0;
        for (const c of chunks) {
          all.set(c, at);
          at += c.length;
          c.fill(0);
        }
        const data = bytesToB64(all);
        all.fill(0);
        try {
          await this.link!.input.request({ op: "write", data });
        } catch (e) {
          if (e instanceof Refused) {
            this.setState({ kind: "closed", error: e.message, exit: null });
            return;
          }
          // The keystrokes typed into the break are lost rather than risk
          // being typed twice; the link is made anew for the next ones.
          if (!(await this.mend())) {
            this.events.onBroken(String(e));
            return;
          }
        }
      }
    } finally {
      this.writing = false;
    }
  }

  private resized(cols: number, rows: number) {
    if (this.resizeTimer) clearTimeout(this.resizeTimer);
    this.resizeTimer = setTimeout(() => {
      if (this.state.kind !== "open" || this.stopped || !this.link) return;
      this.link.input.request({ op: "resize", cols, rows }).catch(() => {});
    }, 120);
  }

  /// The person's answer about an unknown host.
  async trust(answer: boolean): Promise<void> {
    await this.link?.input.request({ op: "trust", answer });
  }

  /// Ends the shell.
  async close(): Promise<void> {
    if (!this.link || !this.session) return;
    await this.link.input.request({ op: "close" });
  }
}
