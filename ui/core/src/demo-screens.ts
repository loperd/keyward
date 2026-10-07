// The demo's declared screens: what a plugin's `view` and `act` would answer
// for the demo's Kubernetes clusters, in the wire's own shape (keyward-ui's
// `Page` and `Reply`), so the stand and the tests draw them through the same
// reader and the same kit as a real plugin's. The pods, the logs and the
// shell are made up; the shell echoes what is typed.
import { tx } from "./i18n";

/// The demo's words for its screens: keys of its dictionary (demo-backend's
/// WORDS_SRC), or values as they are.
const k = (key: string, args?: Record<string, unknown>) => (args ? { key, args } : { key });
const raw = (s: string) => ({ raw: s });

type Pod = { name: string; ns: string; phase: string; ready: [number, number]; restarts: number; node: string; age: number };

/// The demo clock's "now", in seconds: the screens' ages read from it.
const now = () => Math.floor(Date.now() / 1000);

// boundary: the wire's words, as a plugin says them.
const PODS: Pod[] = [
  { name: "api-7d9f8b6c4-x2kqp", ns: "prod", phase: "Running", ready: [2, 2], restarts: 0, node: "node-a", age: 3 * 86400 },
  { name: "api-7d9f8b6c4-m8wzt", ns: "prod", phase: "Running", ready: [2, 2], restarts: 1, node: "node-b", age: 3 * 86400 },
  { name: "worker-5c8d7f9b8-qq4lp", ns: "prod", phase: "CrashLoopBackOff", ready: [0, 1], restarts: 14, node: "node-b", age: 7200 },
  { name: "postgres-0", ns: "data", phase: "Running", ready: [1, 1], restarts: 0, node: "node-c", age: 21 * 86400 },
  { name: "migrate-28817340-7xk2b", ns: "data", phase: "Pending", ready: [0, 1], restarts: 0, node: "", age: 120 },
];

const LOGS = "2026-10-07T21:00:01Z listening on :8080\n2026-10-07T21:00:04Z GET /health 200 0.4ms\n2026-10-07T21:00:09Z GET /api/items 200 12.1ms\n";
const MANIFEST = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n  namespace: prod\nspec:\n  replicas: 2\n  template:\n    spec:\n      containers:\n        - name: api\n          image: registry.demo.example/api:1.42.0\n";

// boundary: the wire's words, as a plugin says them.
const tone = (phase: string) => (phase === "Running" ? "ok" : phase === "Pending" ? "warn" : "bad");

// boundary: the wire's words, as a plugin says them.
function podsTable(cluster: string) {
  return {
    type: "table",
    id: `${cluster}|pods`,
    columns: [
      { id: "name", title: k("colName"), sortable: true },
      { id: "ns", title: k("colNamespace"), sortable: true },
      { id: "ready", title: k("colReady"), sortable: true },
      { id: "status", title: k("colStatus"), sortable: true },
      { id: "restarts", title: k("colRestarts"), sortable: true },
      { id: "age", title: k("colAge"), sortable: true },
    ],
    facets: [
      { id: "ns", title: k("colNamespace"), icon: "folder" },
      { id: "status", title: k("colStatus"), icon: "state" },
    ],
    rows: PODS.map((p) => {
      const at = { cluster, kind: "pods", namespace: p.ns, name: p.name };
      return {
        key: `${p.ns}/${p.name}`,
        cells: {
          name: { type: "text", text: raw(p.name) },
          ns: { type: "text", text: raw(p.ns) },
          ready: { type: "chip", chip: { label: raw(`${p.ready[0]}/${p.ready[1]}`), tone: p.ready[0] >= p.ready[1] ? "ok" : "warn", dot: true } },
          status: { type: "chip", chip: { label: raw(p.phase), tone: tone(p.phase), dot: true } },
          restarts: { type: "text", text: raw(String(p.restarts)) },
          age: { type: "ago", at: now() - p.age },
        },
        facets: { ns: p.ns, status: p.phase },
        sort: { restarts: p.restarts, age: p.age },
        open: { op: "object", payload: at },
        actions: [
          { icon: "terminal", title: k("shell"), action: { op: "object", payload: { ...at, tab: "shell" } } },
          { icon: "trash", title: k("deleteNow"), tone: "bad", action: { op: "delete_object", payload: at, twice: true } },
        ],
      };
    }),
    empty: k("noPods"),
  };
}

// boundary: the wire's words, as a plugin says them.
function configTable(cluster: string) {
  return {
    type: "table",
    id: `${cluster}|config`,
    columns: [
      { id: "name", title: k("colName"), sortable: true },
      { id: "ns", title: k("colNamespace"), sortable: true },
      { id: "keys", title: k("colKeys") },
    ],
    rows: [
      { key: "prod/api-config", cells: { name: { type: "text", text: raw("api-config") }, ns: { type: "text", text: raw("prod") }, keys: { type: "text", text: raw("LOG_LEVEL, PORT") } } },
      { key: "data/pg-tuning", cells: { name: { type: "text", text: raw("pg-tuning") }, ns: { type: "text", text: raw("data") }, keys: { type: "text", text: raw("shared_buffers") } } },
    ],
  };
}

/// A cluster's screen: its tables in tabs, creating an object, asking again.
// boundary: the wire's words, as a plugin says them.
function clusterPage(slug: string, api: string) {
  return {
    title: raw(slug),
    icon: "cube",
    subtitle: raw(api),
    actions: [
      { label: k("create"), icon: "plus", title: k("create"), primary: true, action: { op: "create", payload: { cluster: slug } } },
      { icon: "refresh", title: k("refresh"), action: { op: "refresh" } },
    ],
    body: [
      {
        type: "tabs",
        id: `${slug}|groups`,
        icons_only: true,
        tabs: [
          { id: "pods", title: k("pods"), icon: "stack", load: { op: "table", payload: { cluster: slug, kind: "pods" } }, refresh_ms: 5000 },
          { id: "config", title: k("configMaps"), icon: "tune", body: [configTable(slug)] },
        ],
      },
    ],
  };
}

/// A pod's drawer: its log, its shell, its manifest, and deleting it.
// boundary: the wire's words, as a plugin says them.
function podDrawer(p: { cluster: string; namespace: string; name: string; tab?: string }) {
  const at = { cluster: p.cluster, kind: "pods", namespace: p.namespace, name: p.name };
  return {
    title: raw(p.name),
    icon: "stack",
    subtitle: raw(p.namespace),
    actions: [
      { icon: "edit", title: k("edit"), action: { op: "edit", payload: at } },
      { icon: "trash", title: k("deleteNow"), tone: "bad", action: { op: "delete_object", payload: at, twice: true } },
    ],
    body: [
      {
        type: "tabs",
        id: `${p.cluster}|object`,
        icons_only: true,
        ...(p.tab ? { on: p.tab } : {}),
        tabs: [
          { id: "logs", title: k("logs"), icon: "note", load: { op: "logs_node", payload: at } },
          { id: "shell", title: k("shell"), icon: "terminal", body: [{ type: "terminal", open: { op: "shell_open", payload: at }, read: "shell_read", write: "shell_write", resize: "shell_resize", close: "shell_close" }] },
        ],
      },
      { type: "danger", title: k("deleteTitle", { name: p.name }), hint: k("deleteHint"), button: { label: k("delete"), icon: "trash", title: k("delete"), tone: "bad", action: { op: "delete_object", payload: at, confirm: p.name } } },
    ],
  };
}

const CLUSTER_API: Record<string, string> = {
  "prod-eu-1": "https://k8s.prod.demo.example:6443",
  "staging-eu-1": "https://k8s.staging.demo.example:6443",
  "ops-globex": "https://k8s.ops.globex.example",
};

/// The screen for a route, as the wire carries it.
export function demoView(route: string): unknown {
  const slug = route.startsWith("cluster/") ? route.slice("cluster/".length) : null;
  const api = slug === null ? undefined : CLUSTER_API[slug];
  if (slug === null || api === undefined) throw new Error(`the demo has no screen "${route}"`);
  return clusterPage(slug, api);
}

/// An echo shell: what is typed comes back, a line ends with a prompt.
type Echo = { out: string; wake: (() => void)[]; closed: boolean };
const shells = new Map<string, Echo>();
const enc = new TextEncoder();
const b64 = (s: string) => btoa(String.fromCharCode(...enc.encode(s)));
const unb64 = (s: string) => new TextDecoder().decode(Uint8Array.from(atob(s), (c) => c.charCodeAt(0)));
const say = (e: Echo, s: string) => {
  e.out += s;
  for (const w of e.wake.splice(0)) w();
};

type Payload = Record<string, unknown>;
const field = (p: Payload, key: string) => {
  const v = p[key];
  if (typeof v !== "string") throw new Error(`the demo's "${key}" is not text`);
  return v;
};

/// What an operation answers, as the wire carries it.
// boundary: the wire's words, as a plugin says them.
export async function demoAct(op: string, payload: unknown, form: Readonly<Record<string, string>> | null): Promise<unknown> {
  const p = (payload ?? {}) as Payload;
  switch (op) {
    case "refresh":
      return { refresh: true };
    case "table":
      return { data: { body: [podsTable(field(p, "cluster"))] } };
    case "object":
      return { drawer: podDrawer({ cluster: field(p, "cluster"), namespace: field(p, "namespace"), name: field(p, "name"), ...(typeof p.tab === "string" ? { tab: p.tab } : {}) }) };
    case "logs_node":
      return { data: { body: [{ type: "pre", text: LOGS }] } };
    case "edit":
      return { dialog: { title: k("editTitle", { name: field(p, "name") }), body: [{ type: "editor", text: MANIFEST, check: { op: "editor_check", payload: p }, apply: { op: "editor_apply", payload: p } }] } };
    case "editor_check":
      return { data: { before: MANIFEST, after: field(p, "text") } };
    case "editor_apply":
      return { close_dialog: true, refresh: true, toast: k("applied") };
    case "delete_object":
      return { close_drawer: true, refresh: true, toast: k("deleted") };
    case "create":
      return {
        dialog: {
          title: k("create"),
          body: [
            {
              type: "form",
              fields: [
                { id: "name", label: k("colName"), kind: { kind: "text" } },
                { id: "ns", label: k("colNamespace"), kind: { kind: "select", options: [["prod", raw("prod")], ["data", raw("data")]] } },
                { id: "replicas", label: k("replicas"), kind: { kind: "number", min: 0, max: 10 }, value: "1" },
                { id: "token", label: k("token"), kind: { kind: "secret" }, hint: k("tokenHint") },
              ],
              submit: { label: k("create"), icon: "plus", title: k("create"), primary: true, action: { op: "create_object", payload: { cluster: field(p, "cluster") } } },
            },
          ],
        },
      };
    case "create_object": {
      // A made-up object: what was typed is checked, never kept.
      const name = form?.name ?? "";
      if (!name.trim()) throw new Error(tx("demo.needName"));
      return { close_dialog: true, refresh: true, toast: k("created", { name }) };
    }
    case "shell_open": {
      const stream = `demo-shell-${shells.size + 1}`;
      const e: Echo = { out: "", wake: [], closed: false };
      shells.set(stream, e);
      say(e, `\x1b[2mdemo · ${field(p, "name")}\x1b[0m\r\n$ `);
      return { data: { stream } };
    }
    case "shell_read": {
      const e = shells.get(field(p, "stream"));
      if (!e) throw new Error("the demo has no such shell");
      const cursor = typeof p.cursor === "number" ? p.cursor : 0;
      if (e.out.length <= cursor && !e.closed) await new Promise<void>((r) => e.wake.push(r));
      return { data: { data: b64(e.out.slice(cursor)), cursor: e.out.length, state: e.closed ? "closed" : "open", dropped: false } };
    }
    case "shell_write": {
      const e = shells.get(field(p, "stream"));
      if (!e) throw new Error("the demo has no such shell");
      const typed = unb64(field(p, "data"));
      say(e, typed.replace(/\r/g, "\r\n$ "));
      return { data: null };
    }
    case "shell_resize":
      return { data: null };
    case "shell_close": {
      const e = shells.get(field(p, "stream"));
      if (e) {
        e.closed = true;
        say(e, "");
        shells.delete(field(p, "stream"));
      }
      return { data: null };
    }
    default:
      throw new Error(`the demo does not play "${op}"`);
  }
}

/// The demo's words for its screens, in both languages.
export const SCREEN_WORDS: Record<string, { ru: string; en: string }> = {
  colName: { ru: "Имя", en: "Name" },
  colNamespace: { ru: "Пространство", en: "Namespace" },
  colReady: { ru: "Готово", en: "Ready" },
  colStatus: { ru: "Состояние", en: "Status" },
  colRestarts: { ru: "Перезапуски", en: "Restarts" },
  colAge: { ru: "Возраст", en: "Age" },
  colKeys: { ru: "Ключи", en: "Keys" },
  pods: { ru: "Поды", en: "Pods" },
  configMaps: { ru: "Конфигурации", en: "Config maps" },
  noPods: { ru: "Подов нет", en: "No pods" },
  shell: { ru: "Оболочка", en: "Shell" },
  logs: { ru: "Журнал", en: "Logs" },
  edit: { ru: "Изменить", en: "Edit" },
  editTitle: { ru: "Изменить {name}", en: "Edit {name}" },
  delete: { ru: "Удалить", en: "Delete" },
  deleteNow: { ru: "Удалить", en: "Delete" },
  deleteTitle: { ru: "Удалить {name}", en: "Delete {name}" },
  deleteHint: { ru: "Контроллер поднимет под заново; журнал пропадёт", en: "Its controller brings the pod back; its log is gone" },
  create: { ru: "Создать", en: "Create" },
  created: { ru: "{name} создан", en: "{name} created" },
  needName: { ru: "Нужно имя", en: "A name is needed" },
  replicas: { ru: "Реплики", en: "Replicas" },
  token: { ru: "Токен", en: "Token" },
  tokenHint: { ru: "Уходит зашифрованным, не сохраняется", en: "Sent sealed, never kept" },
  refresh: { ru: "Обновить", en: "Refresh" },
  applied: { ru: "Применено", en: "Applied" },
  deleted: { ru: "Удалено", en: "Deleted" },
};
