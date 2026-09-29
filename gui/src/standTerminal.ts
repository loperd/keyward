// The stand's half of the ssh plugin's terminal: the same sealed link the
// plugin speaks (ECDH P-256, HKDF-SHA256, AES-256-GCM, two lanes, a counter
// per exchange), over a make-believe shell and a made-up health board. The
// page cannot tell it from the plugin, which is the point: the screens are
// photographed against the real protocol.

const SALT = new TextEncoder().encode("keyward terminal v1");
const enc = new TextEncoder();

function b64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function unb64(text: string): Uint8Array<ArrayBuffer> {
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function nonce(counter: number): Uint8Array<ArrayBuffer> {
  const n = new Uint8Array(12);
  new DataView(n.buffer).setBigUint64(4, BigInt(counter));
  return n;
}

type Lane = { open: CryptoKey; seal: CryptoKey; counter: number };
type Link = { input: Lane; output: Lane; session?: string };

type State =
  | { kind: "connecting" }
  | { kind: "verify"; prompt: { host: string; port: number; fingerprint: string; algorithm: string; others: boolean } }
  | { kind: "authenticating" }
  | { kind: "open" }
  | { kind: "closed"; error: string | null; exit: number | null };

type Info = { id: string; entry_id: string; entry_name: string; host: string; port: number; user: string; opened_at: number };

class Shell {
  state: State = { kind: "connecting" };
  version = 0;
  out = "";
  line = "";
  waiters: (() => void)[] = [];
  constructor(public info: Info) {}

  set(state: State) {
    if (this.state.kind === "closed") return;
    this.state = state;
    this.version += 1;
    this.wake();
  }

  print(text: string) {
    this.out += text;
    this.wake();
  }

  wake() {
    const w = this.waiters;
    this.waiters = [];
    for (const f of w) f();
  }

  prompt() {
    this.print(`\x1b[38;5;79m${this.info.user}@${this.info.host.split(".")[0]}\x1b[0m:\x1b[38;5;111m~\x1b[0m$ `);
  }

  type(text: string) {
    for (const ch of text) {
      if (ch === "\r") {
        this.print("\r\n");
        this.run(this.line.trim());
        this.line = "";
      } else if (ch === "\x7f") {
        if (this.line) {
          this.line = this.line.slice(0, -1);
          this.print("\b \b");
        }
      } else if (ch === "\x03") {
        this.print("^C\r\n");
        this.line = "";
        this.prompt();
      } else if (ch >= " ") {
        this.line += ch;
        this.print(ch);
      }
    }
  }

  run(cmd: string) {
    const host = this.info.host;
    const outputs: Record<string, string> = {
      "": "",
      whoami: `${this.info.user}\r\n`,
      hostname: `${host}\r\n`,
      uptime: " 14:02:11 up 41 days,  3:17,  1 user,  load average: 0.08, 0.11, 0.09\r\n",
      ls: "\x1b[1;38;5;111mdeploy\x1b[0m  \x1b[1;38;5;111mlogs\x1b[0m  docker-compose.yml  README.md\r\n",
      "df -h": "Filesystem      Size  Used Avail Use% Mounted on\r\n/dev/nvme0n1p1   80G   31G   49G  39% /\r\n",
      "docker ps": "CONTAINER ID   IMAGE            STATUS          NAMES\r\n3f9c1a2b7d10   api:2026.09.3    Up 6 days       api\r\n8e41d0c5a9f2   postgres:17      Up 41 days      db\r\n",
    };
    if (cmd === "exit") {
      this.print("logout\r\n");
      this.set({ kind: "closed", error: null, exit: 0 });
      return;
    }
    if (cmd === "clear") {
      this.print("\x1b[2J\x1b[H");
    } else if (cmd in outputs) {
      this.print(outputs[cmd]);
    } else {
      this.print(`bash: ${cmd.split(" ")[0]}: command not found\r\n`);
    }
    this.prompt();
  }
}

const links = new Map<string, Link>();
const shells = new Map<string, Shell>();
/// Hosts the stand's "person" has already trusted.
const trusted = new Set(["git.prod.demo.example", "api.prod.demo.example"]);
let ids = 0;

const DEMO_TARGETS = [
  { entry_id: "i3", entry_name: "id_ed25519 — production", host: "git.prod.demo.example", port: null, user: "git", pattern: "git@git.prod.demo.example", recent: false },
  { entry_id: "i3", entry_name: "id_ed25519 — production", host: "api.prod.demo.example", port: null, user: "deploy", pattern: "deploy@api.prod.demo.example", recent: false },
  { entry_id: "i9", entry_name: "id_ed25519 — staging", host: "db.staging.demo.example", port: 2222, user: "ubuntu", pattern: "", recent: true },
  { entry_id: "k7", entry_name: "legacy-rsa", host: "old.demo.example", port: null, user: "admin", pattern: "admin@old.demo.example", recent: false },
  { entry_id: "i3", entry_name: "id_ed25519 — production", host: "bastion.demo.example", port: null, user: null, pattern: "bastion.demo.example", recent: false },
];

const now = () => Math.floor(Date.now() / 1000);
let checkedAt = now() - 7 * 60;
let running = false;

function report() {
  const at = checkedAt;
  return {
    running,
    checked_at: at,
    keys: [
      {
        entry_id: "k3",
        entry_name: "break-glass key",
        status: "unbound",
        checks: [],
      },
      {
        entry_id: "i3",
        entry_name: "id_ed25519 — production",
        status: "reachable",
        checks: [
          { host: "bastion.demo.example", port: 22, user: null, status: "reachable", latency_ms: 64, detail: null, fingerprint: null, checked_at: at },
          { host: "api.prod.demo.example", port: 22, user: "deploy", status: "ok", latency_ms: 51, detail: null, fingerprint: null, checked_at: at },
          { host: "git.prod.demo.example", port: 22, user: "git", status: "ok", latency_ms: 38, detail: null, fingerprint: null, checked_at: at },
        ],
      },
      {
        entry_id: "i9",
        entry_name: "id_ed25519 — staging",
        status: "rejected",
        checks: [
          { host: "db.staging.demo.example", port: 2222, user: "ubuntu", status: "rejected", latency_ms: 73, detail: null, fingerprint: null, checked_at: at },
          { host: "build.staging.demo.example", port: 22, user: "ci", status: "unreachable", latency_ms: null, detail: 'err.sshUnreachable {"host":"build.staging.demo.example","reason":"timed out"}', fingerprint: null, checked_at: at },
        ],
      },
      {
        entry_id: "k7",
        entry_name: "legacy-rsa",
        status: "host_changed",
        checks: [
          {
            host: "old.demo.example",
            port: 22,
            user: "admin",
            status: "host_changed",
            latency_ms: null,
            detail: 'err.sshHostKeyChanged {"host":"old.demo.example","port":22,"fingerprint":"SHA256:demoChangedKeyFingerprint0000000000000000000"}',
            fingerprint: "SHA256:demoChangedKeyFingerprint0000000000000000000",
            checked_at: at,
          },
        ],
      },
    ],
  };
}

async function laneKeys(secret: ArrayBuffer, lane: string, page: Uint8Array, mine: Uint8Array): Promise<Lane> {
  const derive = async (direction: string, usage: KeyUsage) => {
    const label = enc.encode(`${direction} ${lane}`);
    const info = new Uint8Array(label.length + page.length + mine.length);
    info.set(label, 0);
    info.set(page, label.length);
    info.set(mine, label.length + page.length);
    const ikm = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: SALT, info }, ikm, { name: "AES-GCM", length: 256 }, false, [usage]);
  };
  return { open: await derive("page to plugin", "decrypt"), seal: await derive("plugin to page", "encrypt"), counter: 0 };
}

function start(shell: Shell) {
  setTimeout(() => {
    if (trusted.has(shell.info.host)) auth(shell);
    else
      shell.set({
        kind: "verify",
        prompt: { host: shell.info.host, port: shell.info.port, fingerprint: "SHA256:k7Qm1vD0demoZ8y2m4Rk1pS9fXcW0uLhTnB3eGdAa5o", algorithm: "ssh-ed25519", others: false },
      });
  }, 700);
}

function auth(shell: Shell) {
  shell.set({ kind: "authenticating" });
  setTimeout(() => {
    shell.set({ kind: "open" });
    shell.print(`Welcome to Ubuntu 24.04.3 LTS (GNU/Linux 6.8.0-45-generic x86_64)\r\n\r\n  System load:  0.08          Processes:     142\r\n  Usage of /:   39% of 80GB   Users:         1\r\n\r\nLast login: Mon Sep 28 18:22:04 2026 from 10.0.0.12\r\n`);
    shell.prompt();
  }, 1100);
}

function input(link: Link, req: Record<string, unknown>): unknown {
  const shell = link.session ? shells.get(link.session) : undefined;
  switch (req.op) {
    case "open": {
      const target = req.target as { entry_id?: string; host: string; port?: number | null; user?: string | null };
      const known = DEMO_TARGETS.find((t) => t.host === target.host);
      const user = target.user || known?.user;
      if (!user) return { error: `err.sshLoginRequired {"host":"${target.host}"}` };
      ids += 1;
      const info: Info = {
        id: `s${ids}`,
        entry_id: target.entry_id ?? known?.entry_id ?? "i3",
        entry_name: known?.entry_name ?? "id_ed25519 — production",
        host: target.host,
        port: target.port ?? known?.port ?? 22,
        user,
        opened_at: now(),
      };
      const s = new Shell(info);
      shells.set(info.id, s);
      link.session = info.id;
      start(s);
      return { session: info, state: s.state };
    }
    case "attach": {
      const s = shells.get(String(req.session));
      if (!s) return { error: "err.sshSessionClosed" };
      link.session = s.info.id;
      return { session: s.info, state: s.state };
    }
    case "write":
      if (!shell || shell.state.kind === "closed") return { error: "err.sshSessionClosed" };
      shell.type(new TextDecoder().decode(unb64(String(req.data))));
      return null;
    case "resize":
      return shell ? null : { error: "err.sshNoSession" };
    case "trust":
      if (!shell || shell.state.kind !== "verify") return { error: "err.sshNothingToTrust" };
      if (req.answer) {
        trusted.add(shell.info.host);
        auth(shell);
      } else {
        shell.set({ kind: "closed", error: `err.sshHostKeyDeclined {"host":"${shell.info.host}","fingerprint":"SHA256:k7Qm1vD0demoZ8y2m4Rk1pS9fXcW0uLhTnB3eGdAa5o"}`, exit: null });
      }
      return null;
    case "close":
      if (shell) {
        shell.set({ kind: "closed", error: null, exit: null });
        shells.delete(shell.info.id);
      }
      return null;
    default:
      return { error: "err.sshTerminalBroken" };
  }
}

async function read(link: Link, req: Record<string, unknown>): Promise<unknown> {
  const shell = link.session ? shells.get(link.session) : undefined;
  if (!shell) return { error: "err.sshNoSession" };
  const cursor = Number(req.cursor);
  const version = Number(req.version);
  const until = Date.now() + Math.min(Number(req.wait_ms) || 0, 15000);
  while (shell.out.length <= cursor && shell.version === version && shell.state.kind !== "closed" && Date.now() < until) {
    await new Promise<void>((done) => {
      shell.waiters.push(done);
      setTimeout(done, Math.max(0, until - Date.now()));
    });
  }
  const data = shell.out.slice(Math.min(cursor, shell.out.length));
  return { data: b64(enc.encode(data)), cursor: shell.out.length, dropped: false, state: shell.state, version: shell.version };
}

export const STAND_TERMINAL: Record<string, (p: Record<string, unknown>) => unknown> = {
  term_link: async ({ public: pagePublic }) => {
    const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const mine = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    const page = unb64(String(pagePublic));
    const theirs = await crypto.subtle.importKey("raw", page, { name: "ECDH", namedCurve: "P-256" }, false, []);
    const secret = await crypto.subtle.deriveBits({ name: "ECDH", public: theirs }, pair.privateKey, 256);
    ids += 1;
    const id = `l${ids}`;
    links.set(id, { input: await laneKeys(secret, "input", page, mine), output: await laneKeys(secret, "output", page, mine) });
    return { link: id, public: b64(mine) };
  },
  term: async ({ link: id, lane: name, sealed }) => {
    const link = links.get(String(id));
    if (!link) throw 'err.sshLinkGone';
    const lane = name === "output" ? link.output : link.input;
    const aad = enc.encode(String(name));
    const n = nonce(lane.counter);
    let plain: Uint8Array;
    try {
      plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: n, additionalData: aad }, lane.open, unb64(String(sealed))));
    } catch {
      throw "err.channelFailed";
    }
    const req = JSON.parse(new TextDecoder().decode(plain)) as Record<string, unknown>;
    const answer = name === "output" ? await read(link, req) : input(link, req);
    const out = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: n, additionalData: aad }, lane.seal, enc.encode(JSON.stringify(answer ?? null))));
    lane.counter += 1;
    return { sealed: b64(out) };
  },
  term_sessions: () => [...shells.values()].map((s) => ({ ...s.info, state: s.state })),
  term_targets: () => DEMO_TARGETS,
  term_forget_host: () => 0,
  health: () => report(),
  health_run: async () => {
    running = true;
    await new Promise((done) => setTimeout(done, 1200));
    running = false;
    checkedAt = now();
    return report();
  },
};
