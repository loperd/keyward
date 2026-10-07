// A backend over the demo vault, for the stand and the tests: the catalogue
// lives in memory, changes are announced like a sync would, and every secret
// it hands out is a made-up value marked "demo-" — never anything that looks
// like a real password. It also brings what a plugin would: SSH hosts, keys
// and a topology, and Kubernetes clusters, as nodes of the graph with pages in
// the core's vocabulary and words of their own.
import { type AppSettings, LanguageChoice, LockAction, LockTimeoutKind, type SettingsPatch, ThemeChoice, type UnlockState, type BrowserExtensions, type AccountProfile, KdfKind, type TwoFactorStatus } from "./settings/types";
import { AccountOp, type AccountWrite } from "./verbs/spec";
import { type Account, type Backend, type Capabilities, type Change, type Copied, type LoginStep, type Revealed, type Session, TwoFactorProvider, SessionState, ChangeKind, LoginStepKind } from "./backend";
import { DEMO, DEMO_NOW } from "./demo";
import { registerWords, t, type Text, type Words, Lang } from "./i18n";
import { type Catalog, type ItemDetail, type Field, type SecretRef, type Totp, Level, ItemKind, SecretField } from "./model/types";
import { type Contribution, type Directory, type Node, MapKind, NodeKind, ResultGroup, ResultKind } from "./path/directory";
import type { Place } from "./path/places";
import type { Verb } from "./path/query";
import { type DocSpec, type Block, type MarkSpec, LeadTile, Hue } from "./doc/spec";
import { type MapEdge, type MapModel, type MapNode, type Link, EdgeKind } from "./map/types";
import { itemPoint, pluginPoint, placeText } from "./map/model";
import { type Preview, PreviewKind } from "./verbs/spec";

const W = (ru: string, en: string) => ({ ru, en });
const P = (ru: [string, string, string], en: [string, string]) => ({
  ru: { one: ru[0], few: ru[1], many: ru[2], other: ru[2] },
  en: { one: en[0], other: en[1] },
});
type Entry = ReturnType<typeof W> | ReturnType<typeof P>;
const WORDS_SRC: Record<string, Entry> = {
  ssh: W("SSH", "SSH"),
  sshSub: W("6 хостов · 2 ключа", "6 hosts · 2 keys"),
  sshWhy: W("db-1 отклонил ключ", "db-1 refused the key"),
  sshShort: W("db-1 отказал", "db-1 refused"),
  hosts: W("Хосты", "Hosts"),
  keys: W("Ключи", "Keys"),
  topology: W("Топология SSH", "SSH topology"),
  topologySub: W("Ключи → хосты → кластеры", "Keys → hosts → clusters"),
  other: W("Другие", "Other"),
  k8sSub: W("3 кластера", "3 clusters"),
  k8sWhy: W("Токен ops-globex истекает через 5 дней", "The ops-globex token expires in 5 days"),
  tokenExpiring: W("Токен истекает", "Token expiring"),
  expiring: W("Истекает", "Expiring"),
  contexts: P(["{ver} · {n} контекст", "{ver} · {n} контекста", "{ver} · {n} контекстов"], ["{ver} · {n} context", "{ver} · {n} contexts"]),
  opens: W("Открывается · {ago}", "Opens · {ago}"),
  pkOk: W("PK_OK · {ago}", "PK_OK · {ago}"),
  refusedAgo: W("Сервер отказал · {ago}", "Server refused · {ago}"),
  keyRefused: W("Ключ отклонён сервером", "Key refused by the server"),
  hostUnconfirmed: W("Ключ хоста не подтверждён", "Host key not confirmed"),
  noKey: W("Ключ не назначен", "No key assigned"),
  min4: W("4 мин назад", "4 min ago"),
  min11: W("11 мин назад", "11 min ago"),
  min2: W("2 мин назад", "2 min ago"),
  reachable: W("Доступен · 2 мин назад", "Reachable · 2 min ago"),
  reachableShort: W("Доступен", "Reachable"),
  wordOpens: W("Открывается", "Opens"),
  wordRefused: W("Отказ", "Refused"),
  wordUnconfirmed: W("Не подтверждён", "Unconfirmed"),
  wordNoKey: W("Без ключа", "No key"),
  keyAccepted: W("Ключ принят", "Key accepted"),
  keyRefusedShort: W("Ключ отклонён", "Key refused"),
  hostUnconfirmedShort: W("Хост не подтверждён", "Host unconfirmed"),
  clusterNode: W("Узел кластера", "Cluster node"),
  gateway: W("Шлюз к API", "API gateway"),
  tokenFor: W("Токен для kubectl", "Token for kubectl"),
  takesToken: W("{name} берёт токен отсюда", "{name} takes its token from here"),
  opensHosts: P(["Открывает {n} хост", "Открывает {n} хоста", "Открывает {n} хостов"], ["Opens {n} host", "Opens {n} hosts"]),
  dbRefusedFind: W("db-1: ключ отклонён", "db-1: key refused"),
  buildFind: W("build: ключ хоста не подтверждён", "build: host key unconfirmed"),
  kindCommandGit: W("Командный · git", "Command · git"),
  kindCommand: W("Командный", "Command"),
  kindTty: W("TTY", "TTY"),
  laneKeys: W("SSH-ключи", "SSH keys"),
  laneHosts: W("Хосты", "Hosts"),
  laneClusters: W("Кластеры", "Clusters"),
  laneTokens: W("Токены из хранилища", "Tokens from the vault"),
  topoPlace: W("2 ключа · 6 хостов · 3 кластера · Проверено 4 мин назад, без подписи", "2 keys · 6 hosts · 3 clusters · Checked 4 min ago, without signing"),
  tokenOf: W("Токен · {place}", "Token · {place}"),
  findDb: W("db-1 отклонил id_ed25519 — production", "db-1 refused id_ed25519 — production"),
  findBuild: W("build: ключ хоста не подтверждён", "build: host key unconfirmed"),
  findGlobex: W("ops-globex: токен истекает через 5 дней", "ops-globex: token expires in 5 days"),
  findLegacy: W("legacy: ключ не назначен", "legacy: no key assigned"),
  legendUnconfirmed: W("Не подтверждён", "Unconfirmed"),
  legendNode: W("Узел, шлюз", "Node, gateway"),
  sshWhat: W("6 хостов · 2 ключа · Проверка каждые 15 мин", "6 hosts · 2 keys · Checked every 15 min"),
  newTerminal: W("Новый терминал", "New terminal"),
  checkAll: W("Проверить все", "Check all"),
  check: W("Проверить", "Check"),
  edit: W("Изменить", "Edit"),
  more: W("Ещё", "More"),
  openTerminal: W("Открыть терминал", "Open terminal"),
  doorSub: W("Отклонённые маршруты пунктиром, токены кластеров из хранилища", "Refused routes dashed, cluster tokens from the vault"),
  sshNote: W("Ключи не покидают демон: вход подписывается по отпечатку пальца, проверка идёт без подписи.", "Keys never leave the daemon: sign-in is signed with your fingerprint, checks need no signature."),
  lastCheck: W("Последняя проверка", "Last check"),
  refusedFor: W("Сервер не принял id_ed25519 — production", "The server refused id_ed25519 — production"),
  refusedForSub: W("Для root на порту 2222 · 4 минуты назад", "For root on port 2222 · 4 minutes ago"),
  likelyCause: W("Вероятная причина", "Likely cause"),
  likelyCauseSub: W("Ключа нет в authorized_keys или вход root запрещён", "The key is not in authorized_keys or root login is off"),
  hostKeyMatches: W("Ключ хоста совпадает", "Host key matches"),
  connection: W("Подключение", "Connection"),
  username: W("Логин", "Username"),
  port: W("Порт", "Port"),
  rule: W("Правило", "Rule"),
  hostKey: W("Ключ хоста", "Host key"),
  matchesKnown: W("Совпадает с known_hosts", "Matches known_hosts"),
  unknown: W("Неизвестен", "Unknown"),
  openedWith: W("Чем открывается", "Opened with"),
  noVaultKey: W("Ни один ключ хранилища не назначен этому хосту.", "No vault key is assigned to this host."),
  k8sWhat: W("3 кластера · kubeconfig не пишется на диск", "3 clusters · kubeconfig never touches the disk"),
  addCluster: W("Добавить кластер", "Add cluster"),
  clusters: W("Кластеры", "Clusters"),
  cluster: W("Кластер · {ver}", "Cluster · {ver}"),
  clusterSec: W("Кластер", "Cluster"),
  openKubectl: W("Открыть kubectl", "Open kubectl"),
  contextsField: W("Контексты", "Contexts"),
  namespaces: W("Пространства имён", "Namespaces"),
  credentials: W("Учётные данные", "Credentials"),
  tokenEveryCall: W("Токен берётся отсюда при каждом вызове", "The token is taken from here on every call"),
  expires5: W("Истекает через 5 дней", "Expires in 5 days"),
  certFromVault: W("Сертификат из хранилища", "Certificate from the vault"),
  neverDisk: W("Не пишется на диск", "Never written to disk"),
  connect: W("Открыть терминал", "Open terminal"),
  checkKeys: W("Проверить ключи без подписи", "Check keys without signing"),
  connectLede: W("Как {user}, порт {port}. Сессия переживёт закрытие раздела.", "As {user}, port {port}. The session outlives the section."),
  c1: W("Сверю ключ сервера", "Check the server key"),
  c1sub: W("{hk} — подмена будет отвергнута.", "{hk} — a swap is refused."),
  c1subNone: W("Неизвестен — спрошу вас.", "Unknown — I will ask you."),
  c2: W("Подпишу вход в демоне", "Sign the login in the daemon"),
  c2sub: W("После отпечатка пальца; закрытый ключ его не покидает.", "After your fingerprint; the private key never leaves it."),
  c3: W("Открою вкладку", "Open a tab"),
  c3sub: W("Всё, что идёт по терминалу, зашифровано сквозным образом.", "Everything in the terminal is encrypted end to end."),
  nowRefused: W("Сервер отклонил ключ 4 мин назад", "The server refused the key 4 min ago"),
  nowRefusedSub: W("Вход, скорее всего, не удастся", "Sign-in will likely fail"),
  connectGo: W("Подключиться", "Connect"),
  checkLede: W("Серверу предлагается открытый ключ; ответ PK_OK и есть результат.", "The server is offered the public key; its PK_OK is the answer."),
  willCheck: W("Проверю", "Will check"),
  keysAndHosts: W("Ключи и хосты", "Keys and hosts"),
  nothingSigned: W("Ничего не подписывается, ничего не меняется", "Nothing is signed, nothing changes"),
  placeProd: W("Серверы prod", "Prod servers"),
  placeDana: W("Доступ Dana", "Dana's access"),
};
export const DEMO_WORDS: Words = {
  [Lang.Ru]: Object.fromEntries(Object.entries(WORDS_SRC).map(([k, v]) => [k, v.ru])),
  [Lang.En]: Object.fromEntries(Object.entries(WORDS_SRC).map(([k, v]) => [k, v.en])),
};
registerWords("demo", DEMO_WORDS);
const d = (k: keyof typeof WORDS_SRC, args?: Record<string, string | number | Text>): Text => (args ? { ext: `demo.${k}`, args } : { ext: `demo.${k}` });

/// Where a demo host stands.
enum Zone {
  Prod = "prod",
  Staging = "staging",
  Other = "other",
}
type Host = { id: string; slug: string; host: string; user: string; port: number; kind: Text; level: Level; why: Text; short: Text; via: string; hostKey: string | null; zone: Zone; key: string | null; keyLevel: Level; keyWords: Text; cluster: string | null; clusterWords: Text | null };
const HOSTS: Host[] = [
  { id: "ssh:host/git", slug: "git", host: "git.prod.demo.example", user: "git", port: 22, kind: d("kindCommandGit"), level: Level.Healthy, why: d("opens", { ago: d("min4") }), short: d("wordOpens"), via: "git.prod.demo.example", hostKey: "SHA256:7nQw…f2Rt", zone: Zone.Prod, key: "item:key-prod", keyLevel: Level.Healthy, keyWords: d("pkOk", { ago: d("min4") }), cluster: null, clusterWords: null },
  { id: "ssh:host/api-1", slug: "api-1", host: "api-1.prod.demo.example", user: "ubuntu", port: 22, kind: d("kindTty"), level: Level.Healthy, why: d("opens", { ago: d("min4") }), short: d("wordOpens"), via: "*.prod.demo.example", hostKey: "SHA256:Hc2m…0aWe", zone: Zone.Prod, key: "item:key-prod", keyLevel: Level.Healthy, keyWords: d("pkOk", { ago: d("min4") }), cluster: "k8s:prod-eu-1", clusterWords: d("clusterNode") },
  { id: "ssh:host/db-1", slug: "db-1", host: "db-1.prod.demo.example", user: "root", port: 2222, kind: d("kindTty"), level: Level.Critical, why: d("keyRefused"), short: d("wordRefused"), via: "*.prod.demo.example", hostKey: "SHA256:b81K…sYv4", zone: Zone.Prod, key: "item:key-prod", keyLevel: Level.Critical, keyWords: d("refusedAgo", { ago: d("min4") }), cluster: "k8s:prod-eu-1", clusterWords: d("clusterNode") },
  { id: "ssh:host/bastion", slug: "bastion", host: "bastion.staging.demo.example", user: "ubuntu", port: 22, kind: d("kindTty"), level: Level.Healthy, why: d("opens", { ago: d("min11") }), short: d("wordOpens"), via: "bastion.staging.demo.example", hostKey: "SHA256:Ud5r…Mm1o", zone: Zone.Staging, key: "item:key-staging", keyLevel: Level.Healthy, keyWords: d("pkOk", { ago: d("min11") }), cluster: "k8s:staging-eu-1", clusterWords: d("gateway") },
  { id: "ssh:host/build", slug: "build", host: "build.staging.demo.example", user: "ci", port: 22, kind: d("kindCommand"), level: Level.Warning, why: d("hostUnconfirmed"), short: d("wordUnconfirmed"), via: "*.staging.demo.example", hostKey: "SHA256:pp0X…3gQe", zone: Zone.Staging, key: "item:key-staging", keyLevel: Level.Warning, keyWords: d("hostUnconfirmed"), cluster: "k8s:staging-eu-1", clusterWords: d("clusterNode") },
  { id: "ssh:host/legacy", slug: "legacy", host: "legacy.demo.example", user: "admin", port: 22, kind: d("kindTty"), level: Level.Unknown, why: d("noKey"), short: d("wordNoKey"), via: "—", hostKey: null, zone: Zone.Other, key: null, keyLevel: Level.Unknown, keyWords: d("noKey"), cluster: null, clusterWords: null },
];
type Cluster = { id: string; slug: string; api: string; contexts: number; namespaces: number; cred: string | null; level: Level; why: Text; version: string };
const CLUSTERS: Cluster[] = [
  { id: "k8s:prod-eu-1", slug: "prod-eu-1", api: "https://k8s.prod.demo.example:6443", contexts: 3, namespaces: 14, cred: "item:aws", level: Level.Healthy, why: d("reachable"), version: "v1.31.2" },
  { id: "k8s:staging-eu-1", slug: "staging-eu-1", api: "https://k8s.staging.demo.example:6443", contexts: 2, namespaces: 9, cred: null, level: Level.Healthy, why: d("reachable"), version: "v1.31.2" },
  { id: "k8s:ops-globex", slug: "ops-globex", api: "https://k8s.ops.globex.example", contexts: 1, namespaces: 4, cred: "item:pagerduty", level: Level.Warning, why: d("k8sWhy"), version: "v1.30.6" },
];
const hostWord = (l: Level): Text => d(l === Level.Healthy ? "wordOpens" : l === Level.Critical ? "wordRefused" : l === Level.Warning ? "wordUnconfirmed" : "wordNoKey");
const mk = (level: Level, text: Text): MarkSpec => ({ level, text });

function sshDoc(dir: Directory): DocSpec {
  return {
    hero: {
      lead: { tile: LeadTile.Icon, icon: "terminal", hue: Hue.Cyan },
      title: d("ssh"),
      place: [],
      what: d("sshWhat"),
      state: mk(Level.Critical, d("sshWhy")),
      primary: { icon: "terminal", label: d("newTerminal"), act: { none: true } },
      more: [
        { icon: "refresh", label: d("checkAll"), act: { verb: "check keys" } },
        { icon: "map", label: d("topology"), act: { map: { kind: MapKind.Topology, anchor: "plugin:ssh" } } },
        { icon: "more", label: d("more"), act: { none: true } },
      ],
    },
    sections: [
      { title: d("hosts"), count: HOSTS.length, blocks: HOSTS.map((h): Block => ({ ref: h.id, lead: { tile: LeadTile.Plain, icon: "server" }, title: { raw: h.host }, mono: true, context: { raw: `${h.user} · ${h.port}` }, mark: mk(h.level, hostWord(h.level)) })) },
      { title: d("keys"), count: 2, blocks: ["item:key-prod", "item:key-staging"].map((id): Block => {
        const n = dir.node(id);
        return { ref: id, lead: { tile: LeadTile.Node, id }, title: n.name, ...(n.sub ? { context: n.sub } : {}), ...(n.level === Level.Critical ? { mark: mk(Level.Critical, n.short!) } : {}) };
      }) },
      { title: d("topology"), blocks: [{ mapdoor: { kind: MapKind.Topology, anchor: "plugin:ssh" }, title: d("topologySub"), sub: d("doorSub") }] },
    ],
    note: d("sshNote"),
  };
}

function hostDoc(h: Host, dir: Directory): DocSpec {
  return {
    hero: {
      lead: { tile: LeadTile.Icon, icon: "server", hue: Hue.Cyan },
      title: { raw: h.host },
      mono: true,
      place: ["plugin:ssh", "ssh:hosts"],
      what: h.kind,
      state: mk(h.level, h.why),
      primary: { icon: "terminal", label: d("openTerminal"), act: { verb: "connect" } },
      more: [
        { icon: "refresh", label: d("check"), act: { verb: "check keys" } },
        { icon: "map", label: d("topology"), act: { map: { kind: MapKind.Topology, anchor: "plugin:ssh" } } },
        { icon: "edit", label: d("edit"), act: { none: true } },
        { icon: "more", label: d("more"), act: { none: true } },
      ],
    },
    sections: [
      ...(h.level === Level.Critical
        ? [
            {
              title: d("lastCheck"),
              blocks: [
                { sig: Level.Critical, title: d("refusedFor"), sub: d("refusedForSub") },
                { sig: Level.Unknown, title: d("likelyCause"), sub: d("likelyCauseSub") },
                { sig: Level.Healthy, title: d("hostKeyMatches"), sub: { raw: h.hostKey ?? "" } },
              ],
            },
          ]
        : []),
      {
        title: d("connection"),
        blocks: [
          { field: d("username"), value: { raw: h.user }, mono: true },
          { field: d("port"), value: { raw: String(h.port) }, mono: true },
          { field: d("rule"), value: { raw: h.via }, mono: true, faint: { raw: "kw-hostkey" } },
          h.hostKey
            ? { field: d("hostKey"), value: { raw: h.hostKey }, mono: true, mark: h.level === Level.Warning ? mk(Level.Warning, d("wordUnconfirmed")) : mk(Level.Healthy, d("matchesKnown")) }
            : { field: d("hostKey"), value: { raw: "" }, mark: mk(Level.Unknown, d("unknown")) },
        ],
      },
      {
        title: d("openedWith"),
        count: h.key ? 1 : 0,
        blocks: h.key ? [{ ref: h.key, lead: { tile: LeadTile.Node, id: h.key }, title: dir.node(h.key).name, context: h.keyWords, mark: mk(h.keyLevel, hostWord(h.keyLevel)) }] : [{ para: d("noVaultKey") }],
      },
    ],
  };
}

function k8sDoc(): DocSpec {
  return {
    hero: {
      lead: { tile: LeadTile.Icon, icon: "cube", hue: Hue.Sky },
      title: { raw: "Kubernetes" },
      place: [],
      what: d("k8sWhat"),
      state: mk(Level.Warning, d("k8sWhy")),
      primary: { icon: "plus", label: d("addCluster"), act: { none: true } },
      more: [
        { icon: "refresh", label: d("checkAll"), act: { none: true } },
        { icon: "map", label: d("topology"), act: { map: { kind: MapKind.Topology, anchor: "plugin:ssh" } } },
      ],
    },
    sections: [
      { title: d("clusters"), blocks: CLUSTERS.map((c): Block => ({ ref: c.id, lead: { tile: LeadTile.Plain, icon: "cube" }, title: { raw: c.slug }, mono: true, context: { key: "map.placeJoin", args: { a: { raw: c.version }, b: c.why } }, mark: mk(c.level, c.level === Level.Healthy ? d("reachableShort") : d("tokenExpiring")) })) },
    ],
  };
}

function clusterDoc(c: Cluster, dir: Directory): DocSpec {
  const cred = c.cred ? dir.node(c.cred) : null;
  return {
    hero: {
      lead: { tile: LeadTile.Icon, icon: "cube", hue: Hue.Sky },
      title: { raw: c.slug },
      mono: true,
      place: ["plugin:k8s"],
      what: d("cluster", { ver: c.version }),
      state: mk(c.level, c.why),
      primary: { icon: "terminal", label: d("openKubectl"), act: { none: true } },
      more: [
        { icon: "refresh", label: d("check"), act: { none: true } },
        { icon: "map", label: d("topology"), act: { map: { kind: MapKind.Topology, anchor: "plugin:ssh" } } },
        { icon: "edit", label: d("edit"), act: { none: true } },
      ],
    },
    sections: [
      {
        title: d("clusterSec"),
        blocks: [
          { field: { raw: "API" }, value: { raw: c.api }, mono: true },
          { field: d("contextsField"), value: { raw: String(c.contexts) } },
          { field: d("namespaces"), value: { raw: String(c.namespaces) } },
        ],
      },
      {
        title: d("credentials"),
        blocks: [
          cred
            ? { ref: cred.id, lead: { tile: LeadTile.Node, id: cred.id }, title: cred.name, context: d("tokenEveryCall"), mark: c.level === Level.Warning ? mk(Level.Warning, d("expires5")) : mk(Level.Healthy, { key: "level.healthy" }) }
            : { ref: null, lead: { tile: LeadTile.Plain, icon: "key" }, title: d("certFromVault"), context: d("neverDisk"), mark: mk(Level.Healthy, { key: "level.healthy" }) },
        ],
      },
    ],
  };
}

function topology(dir: Directory): MapModel {
  const nodes: MapNode[] = [];
  const edges: MapEdge[] = [];
  for (const k of ["item:key-prod", "item:key-staging"]) nodes.push(itemPoint(dir, k, 0));
  for (const h of HOSTS) nodes.push(pluginPoint(dir, h.id, 1));
  for (const c of CLUSTERS) nodes.push(pluginPoint(dir, c.id, 2));
  for (const t of ["item:aws", "item:pagerduty"]) {
    const p = itemPoint(dir, t, 3);
    p.sub = d("tokenOf", { place: placeText(dir, dir.node(t)) });
    p.marks = [];
    nodes.push(p);
  }
  for (const h of HOSTS)
    if (h.key)
      edges.push({
        a: h.key,
        b: h.id,
        kind: h.keyLevel === Level.Critical ? EdgeKind.Refused : EdgeKind.Route,
        ...(h.keyLevel === Level.Critical ? { level: Level.Critical as const, chip: true } : h.keyLevel === Level.Warning ? { level: Level.Warning as const } : {}),
        words: h.keyLevel === Level.Critical ? d("keyRefusedShort") : h.keyLevel === Level.Warning ? d("hostUnconfirmedShort") : d("keyAccepted"),
      });
  for (const h of HOSTS) if (h.cluster) edges.push({ a: h.id, b: h.cluster, kind: EdgeKind.In, words: h.clusterWords! });
  for (const c of CLUSTERS) if (c.cred) edges.push({ a: c.id, b: c.cred, kind: EdgeKind.Token, ...(c.level === Level.Warning ? { level: Level.Warning as const } : {}), words: c.level === Level.Warning ? d("tokenExpiring") : { key: "map.token" } });
  return {
    nodes,
    edges,
    lanes: [d("laneKeys"), d("laneHosts"), d("laneClusters"), d("laneTokens")],
    pivot: 1,
    title: d("topology"),
    place: d("topoPlace"),
    findings: [
      { level: Level.Critical, text: d("findDb"), focus: "ssh:host/db-1" },
      { level: Level.Warning, text: d("findBuild"), focus: "ssh:host/build" },
      { level: Level.Warning, text: d("findGlobex"), focus: "k8s:ops-globex" },
      { level: Level.Unknown, text: d("findLegacy"), focus: "ssh:host/legacy" },
    ],
    legend: [
      { kind: EdgeKind.Route, text: d("keyAccepted") },
      { kind: EdgeKind.Refused, level: Level.Critical, text: { key: "map.refused" } },
      { kind: EdgeKind.Route, level: Level.Warning, text: d("legendUnconfirmed") },
      { kind: EdgeKind.In, text: d("legendNode") },
      { kind: EdgeKind.Token, text: { key: "map.token" } },
    ],
  };
}

function connectPreview(_dir: Directory, obj: string): Preview {
  const h = HOSTS.find((x) => x.id === obj)!;
  return {
    kind: PreviewKind.Ready,
    target: obj,
    title: d("connect"),
    lede: d("connectLede", { user: h.user, port: h.port }),
    steps: [
      { title: d("c1"), sub: h.hostKey ? d("c1sub", { hk: h.hostKey }) : d("c1subNone") },
      { title: d("c2"), sub: d("c2sub") },
      { title: d("c3"), sub: d("c3sub") },
    ],
    ...(h.level === Level.Critical ? { now: [{ level: Level.Critical, title: d("nowRefused"), sub: d("nowRefusedSub") }] } : {}),
    go: d("connectGo"),
    note: { key: "verb.fingerprint" },
    effect: { none: true },
  };
}

function checkPreview(dir: Directory, obj: string): Preview {
  const n = dir.node(obj);
  const hs = HOSTS.filter((h) => (n.id.startsWith("ssh:host/") ? h.id === obj : n.item ? h.key === obj : true));
  return {
    kind: PreviewKind.Ready,
    target: obj,
    title: d("checkKeys"),
    lede: d("checkLede"),
    steps: [],
    changes: { rows: hs.map((h) => ({ lead: { tile: LeadTile.Plain, icon: "server" }, name: { raw: h.slug }, mono: true, from: mk(h.level, hostWord(h.level)), to: mk(Level.Unknown, d("willCheck")) })), count: hs.length },
    stays: [{ level: Level.Healthy, title: d("keysAndHosts"), sub: d("nothingSigned") }],
    go: d("check"),
    effect: { none: true },
  };
}

const isHost = (n: Node | null) => !!n && n.id.startsWith("ssh:host/");
const DEMO_VERBS: Verb[] = [
  { id: "connect", name: d("connect"), applies: isHost, preview: connectPreview, example: () => "ssh:host/api-1" },
  {
    id: "check keys",
    name: d("checkKeys"),
    applies: (n) => isHost(n) || ["plugin:ssh", "ssh:hosts", "ssh:keys"].includes(n?.id ?? "") || n?.item?.kind === ItemKind.SshKey,
    preview: checkPreview,
    example: () => "plugin:ssh",
  },
];

/// The demo's plugin: SSH and Kubernetes.
export function demoContributions(): Contribution[] {
  const zone = (z: Host["zone"]) => HOSTS.filter((h) => h.zone === z).map((h) => ({ id: h.id }));
  const links: Link[] = [
    ...HOSTS.filter((h) => h.key).map(
      (h): Link => ({
        from: h.id,
        to: h.key!,
        kind: h.keyLevel === Level.Critical ? EdgeKind.Refused : EdgeKind.Route,
        ...(h.keyLevel === Level.Critical ? { level: Level.Critical as const } : h.keyLevel === Level.Warning ? { level: Level.Warning as const } : {}),
        words: h.keyWords,
        short: hostWord(h.keyLevel),
      }),
    ),
    ...HOSTS.filter((h) => h.cluster).map((h): Link => ({ from: h.id, to: h.cluster!, kind: EdgeKind.In, words: h.clusterWords!, short: h.clusterWords! })),
    ...CLUSTERS.filter((c) => c.cred).map(
      (c): Link => ({ from: c.id, to: c.cred!, kind: EdgeKind.Token, ...(c.level === Level.Warning ? { level: Level.Warning as const } : {}), words: d("tokenFor"), short: d("expiring"), finding: d("takesToken", { name: c.slug }) }),
    ),
  ];
  const ssh: Contribution = {
    id: "demo",
    root: { id: "plugin:ssh", kind: NodeKind.Plugin, slug: "ssh", name: d("ssh"), icon: "terminal", hue: Hue.Cyan, sub: d("sshSub"), level: Level.Critical, why: d("sshWhy"), short: d("sshShort"), kids: () => [{ id: "ssh:hosts" }, { id: "ssh:keys" }, { id: "ssh:topology" }], doc: sshDoc },
    nodes: [
      {
        id: "ssh:hosts",
        kind: NodeKind.Plugin,
        slug: "hosts",
        name: d("hosts"),
        icon: "server",
        count: HOSTS.length,
        level: Level.Critical,
        wide: true,
        kids: () => [{ heading: { raw: "prod.demo.example" } }, ...zone(Zone.Prod), { heading: { raw: "staging.demo.example" } }, ...zone(Zone.Staging), { heading: d("other") }, ...zone(Zone.Other)],
        doc: sshDoc,
      },
      { id: "ssh:keys", kind: NodeKind.Plugin, slug: "keys", name: d("keys"), icon: "key", count: 2, level: Level.Critical, wide: true, kids: () => [{ id: "item:key-prod" }, { id: "item:key-staging" }], doc: sshDoc },
      { id: "ssh:topology", kind: NodeKind.Plugin, slug: "topology", name: d("topology"), icon: "map", sub: d("topologySub"), level: Level.Critical, map: { kind: MapKind.Topology, anchor: "plugin:ssh" } },
      ...HOSTS.map(
        (h): Omit<Node, "home"> => ({
          id: h.id,
          kind: NodeKind.Plugin,
          slug: h.slug,
          name: { raw: h.host },
          rowName: { raw: h.slug },
          icon: "server",
          sub: { raw: `${h.user}@ · ${h.port}` },
          mono: true,
          subMono: true,
          level: h.level,
          why: h.why,
          short: h.short,
          result: { group: ResultGroup.Hosts, kind: ResultKind.Host, orgId: null, place: ["plugin:ssh", "ssh:hosts"], haystack: `${h.host} ${h.user}`.toLowerCase() },
          doc: (dir) => hostDoc(h, dir),
        }),
      ),
    ],
    homes: {
      "ssh:hosts": ["plugin:ssh", "ssh:hosts"],
      "ssh:keys": ["plugin:ssh", "ssh:keys"],
      "ssh:topology": ["plugin:ssh", "ssh:topology"],
      ...Object.fromEntries(HOSTS.map((h) => [h.id, ["plugin:ssh", "ssh:hosts", h.id]])),
    },
    signals: {
      "key-prod": { level: Level.Critical, why: d("sshWhy"), short: d("wordRefused") },
      "key-staging": { level: Level.Healthy, why: d("opensHosts", { n: 2 }), short: { key: "level.healthy" } },
    },
    links,
    topology,
    verbs: DEMO_VERBS,
  };
  const k8s: Contribution = {
    id: "demo",
    root: { id: "plugin:k8s", kind: NodeKind.Plugin, slug: "kubernetes", name: { raw: "Kubernetes" }, icon: "cube", hue: Hue.Sky, sub: d("k8sSub"), level: Level.Warning, why: d("k8sWhy"), short: d("tokenExpiring"), wide: true, kids: () => CLUSTERS.map((c) => ({ id: c.id })), doc: () => k8sDoc() },
    nodes: CLUSTERS.map(
      (c): Omit<Node, "home"> => ({
        id: c.id,
        kind: NodeKind.Plugin,
        slug: c.slug,
        name: { raw: c.slug },
        icon: "cube",
        sub: d("contexts", { ver: c.version, n: c.contexts }),
        mono: true,
        level: c.level,
        why: c.why,
        short: c.level === Level.Warning ? d("tokenExpiring") : d("reachableShort"),
        result: { group: ResultGroup.Clusters, kind: ResultKind.Cluster, orgId: null, place: ["plugin:k8s"], haystack: `${c.slug} ${c.api}`.toLowerCase() },
        doc: (dir) => clusterDoc(c, dir),
      }),
    ),
    homes: Object.fromEntries(CLUSTERS.map((c) => [c.id, ["plugin:k8s", c.id]])),
  };
  return [ssh, k8s];
}

/// Places the demo offers beyond the window's own.
export const DEMO_PLACES: Place[] = [
  { id: "prod", name: d("placeProd"), line: "host:*.prod.*", icon: "server" },
  { id: "dana", name: d("placeDana"), line: "acme › acme-members › dana-whitfield", icon: "person" },
];

/// A demo value: what a reveal shows, recognisably fake.
const demoValue = (ref: SecretRef) => `demo-${ref.field === SecretField.Custom ? ref.name.toLowerCase().replace(/\W+/g, "-") : ref.field}-${ref.itemId}`;

/// Where the demo session starts, and what its sign-in asks for: the stand's
/// handles for showing the gate (`?locked=1`, `?signin=1`, `?twofactor=1`).
export type DemoOptions = {
  start?: SessionState;
  /// Several accounts side by side, as on the desktop: two more beside the
  /// demo's own, to switch to.
  accounts?: boolean;
  /// The sign-in asks for a second factor (an app's code or an email's).
  twoFactor?: boolean;
  /// The sign-in then asks for the new device's code.
  newDevice?: boolean;
  /// The app lets a person choose the server, as the desktop does.
  chooseServer?: boolean;
  /// A PIN is set for the locked account.
  pin?: boolean;
  /// Touch ID is set up for the locked account.
  biometric?: boolean;
  /// The vault to serve instead of the demo's (the stand's `?synthetic=N`).
  catalog?: Catalog;
  /// How long each read takes, in milliseconds (the stand's `?slow=MS`): the
  /// session, the catalogue, the plugins' places, an item and its code wait
  /// this long, and the members come in a change of the catalogue of their
  /// own after twice as long, as the desktop's do — so every loading state
  /// can be seen.
  slow?: number;
  /// The settings it starts with, over the daemon's defaults (the stand's
  /// language).
  settings?: Partial<AppSettings>;
};

/// The demo's refusals: a password or code of exactly this is refused, so the
/// stand can show an error.
export const DEMO_WRONG = "wrong";

/// The settings the demo starts with: the daemon's defaults.
export const DEMO_SETTINGS: AppSettings = {
  lockTimeout: { kind: LockTimeoutKind.Minutes, minutes: 15 },
  lockAction: LockAction.Lock,
  touchIdOnLaunch: true,
  touchIdForSecrets: false,
  clipboardClearSeconds: 30,
  biometricGraceSeconds: 60,
  showWebsiteIcons: true,
  hideOnCopy: false,
  keepInTray: true,
  keepInDock: false,
  allowScreenCapture: false,
  startOnLogin: true,
  theme: ThemeChoice.System,
  accentColor: null,
  // The reference language, as the window starts in; the stand says its own.
  language: LanguageChoice.Ru,
};

export class DemoBackend implements Backend {
  readonly caps: Capabilities;
  private data: Catalog = structuredClone(DEMO);
  /// What `DemoWrites` keeps of the items it saved: their fields as a draft
  /// wrote them, and the values typed into them. Read before the demo's own.
  written: { item(id: string): ItemDetail | null; value(ref: SecretRef): string | null } | null = null;
  private readonly listeners = new Set<(c: Change) => void>();
  /// The next change the server refuses: lets the stand show a rollback.
  failNext: string | null = null;
  /// What was copied last, for the tests: never a real secret.
  lastCopied: string | null = null;
  readonly server = "vault.demo.example";
  private state: SessionState;
  /// The accounts beside the demo's own (`accounts`), and whether a new one
  /// is being added.
  private others: Account[] = [
    { id: "ops", email: "ops@acme.example", server: "https://vault.acme.example", active: false, state: SessionState.Locked },
    { id: "home", email: "alex.morgan@mail.example", server: "https://vault.bitwarden.eu", active: false, state: SessionState.LoggedOut },
  ];
  private adding = false;
  private pending: LoginStepKind.TwoFactor | LoginStepKind.NewDevice | null = null;
  private opts: DemoOptions;
  /// What the gate sent, for the tests: never a password.
  readonly calls: string[] = [];
  /// Whether the members are in (at once, unless the demo is slow).
  private membersIn: boolean;
  private membersTimer: ReturnType<typeof setTimeout> | null = null;

  /// A read's wait, where the demo is slow.
  private async wait() {
    if (this.opts.slow) await new Promise((r) => setTimeout(r, this.opts.slow));
  }

  constructor(opts: DemoOptions = {}) {
    this.opts = opts;
    if (opts.catalog) this.data = structuredClone(opts.catalog);
    this.state = opts.start ?? SessionState.Unlocked;
    this.appSettings = { ...structuredClone(DEMO_SETTINGS), ...structuredClone(opts.settings ?? {}) };
    if (opts.slow !== undefined && !(Number.isInteger(opts.slow) && opts.slow >= 0)) throw new Error(`a demo's slowness is a whole number of milliseconds, not ${opts.slow}`);
    this.membersIn = !opts.slow;
    this.caps = { chooseServer: opts.chooseServer ?? false, accounts: opts.accounts ?? false, biometric: true, plugins: true, clipboardClears: true };
  }

  async session(): Promise<Session> {
    await this.wait();
    const email = "alex@acme.example";
    const server = this.server;
    if (this.adding) return { state: SessionState.NeedsSetup };
    switch (this.state) {
      case SessionState.Damaged:
        return { state: SessionState.Damaged, email, server, reason: "err.sessionTampered", canReset: true };
      case SessionState.Unlocked:
        return { state: SessionState.Unlocked, email, server: this.server, name: "Alex Morgan" };
      case SessionState.Locked:
        return { state: SessionState.Locked, email, server, pin: this.opts.pin ?? false, biometric: this.opts.biometric ?? false };
      case SessionState.LoggedOut:
        return { state: SessionState.LoggedOut, email, server };
      case SessionState.NeedsSetup:
        return { state: SessionState.NeedsSetup };
    }
  }
  subscribe(cb: (c: Change) => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }
  private emit(c: Change) {
    for (const l of this.listeners) l(c);
  }
  private open() {
    this.state = SessionState.Unlocked;
    this.adding = false;
    this.pending = null;
    this.emit({ kind: ChangeKind.Session });
  }
  async login(input: { server?: string; identityUrl?: string; email: string; password: string }): Promise<LoginStep> {
    this.calls.push(`login ${input.server ?? "-"}${input.identityUrl ? ` ${input.identityUrl}` : ""} ${input.email}`);
    if (input.password === DEMO_WRONG) throw new Error("err.badPassword");
    if (this.opts.twoFactor) {
      this.pending = LoginStepKind.TwoFactor;
      return { step: LoginStepKind.TwoFactor, providers: [TwoFactorProvider.Authenticator, TwoFactorProvider.Email, TwoFactorProvider.WebAuthn] };
    }
    if (this.opts.newDevice) {
      this.pending = LoginStepKind.NewDevice;
      return { step: LoginStepKind.NewDevice };
    }
    this.open();
    return { step: LoginStepKind.Done };
  }
  async twoFactor(input: { provider: TwoFactorProvider; code: string; remember: boolean }): Promise<LoginStep> {
    if (!this.pending) throw new Error("err.noPendingLogin");
    this.calls.push(`twoFactor ${this.pending} ${input.provider} ${input.remember}`);
    if (input.code === DEMO_WRONG) throw new Error("err.badTwoFactor");
    if (this.pending === LoginStepKind.TwoFactor && this.opts.newDevice) {
      this.pending = LoginStepKind.NewDevice;
      return { step: LoginStepKind.NewDevice };
    }
    this.open();
    return { step: LoginStepKind.Done };
  }
  async sendTwoFactorCode(provider: TwoFactorProvider): Promise<void> {
    if (!this.pending) throw new Error("err.noPendingLogin");
    this.calls.push(`send ${provider}`);
  }
  async unlock(password: string): Promise<void> {
    if (password === DEMO_WRONG) throw new Error("err.badPassword");
    this.open();
  }
  async unlockPin(pin: string): Promise<void> {
    if (pin === DEMO_WRONG) throw new Error("err.pinReset");
    this.open();
  }
  async unlockBiometric(): Promise<void> {
    this.open();
  }
  /// The demo's settings: kept in memory, changed as the daemon changes
  /// them — a refusal when `failNext` says so.
  private appSettings: AppSettings;
  async settings(): Promise<AppSettings> {
    await this.wait();
    return structuredClone(this.appSettings);
  }
  async setSettings(patch: SettingsPatch): Promise<AppSettings> {
    if (this.failNext) {
      const why = this.failNext;
      this.failNext = null;
      throw new Error(why);
    }
    this.appSettings = { ...this.appSettings, ...structuredClone(patch) };
    return structuredClone(this.appSettings);
  }

  /// Touch ID remembered and a PIN set, as the demo's account stands; the
  /// stand's `?pin=1` sets one at the start.
  private unlocks: UnlockState = { biometric: false, biometricProblem: null, pin: false };
  async unlockState(): Promise<UnlockState> {
    await this.wait();
    return { ...this.unlocks, pin: this.unlocks.pin || !!this.opts.pin };
  }
  async account(w: AccountWrite & { secrets: Readonly<Record<string, string>> }): Promise<string | null> {
    const { op, secrets } = w;
    if (this.failNext) {
      const why = this.failNext;
      this.failNext = null;
      throw new Error(why);
    }
    if ((op === AccountOp.RememberBiometric || op === AccountOp.SetPin) && secrets.password === DEMO_WRONG) throw new Error("err.badPassword");
    this.calls.push(`account:${op}`);
    if (op === AccountOp.RememberBiometric) this.unlocks = { ...this.unlocks, biometric: true };
    if (op === AccountOp.ForgetBiometric) this.unlocks = { ...this.unlocks, biometric: false };
    if (op === AccountOp.SetPin) this.unlocks = { ...this.unlocks, pin: true };
    if (op === AccountOp.ClearPin) {
      this.unlocks = { ...this.unlocks, pin: false };
      this.opts = { ...this.opts, pin: false };
    }
    if (w.op !== AccountOp.ForgetBiometric && w.op !== AccountOp.ClearPin && w.op !== AccountOp.Export && w.op !== AccountOp.SetPin && w.op !== AccountOp.RememberBiometric) {
      const password = w.op === AccountOp.ChangePassword ? secrets.current : secrets.password;
      if (password === DEMO_WRONG) throw new Error("err.badPassword");
      if (w.op === AccountOp.ChangeKdf) this.demoProfile = { ...this.demoProfile, kdf: structuredClone(w.kdf) };
      if (w.op === AccountOp.Purge) this.data = { ...this.data, items: this.data.items.filter((i) => i.orgId !== null), folders: [] };
      if (w.op === AccountOp.Deauthorize || w.op === AccountOp.DeleteAccount) this.state = w.op === AccountOp.DeleteAccount ? SessionState.NeedsSetup : SessionState.LoggedOut;
      this.emit({ kind: w.op === AccountOp.Purge ? ChangeKind.Catalog : ChangeKind.Session });
      return null;
    }
    if (w.op === AccountOp.Export) {
      if (secrets.password === DEMO_WRONG) throw new Error("err.badPassword");
      return `~/Downloads/keyward-export.${w.format}`;
    }
    return null;
  }

  /// What the demo's server knows about the person.
  private demoProfile: AccountProfile = {
    email: "alex.morgan@acme.example",
    name: "Alex Morgan",
    hint: null,
    emailVerified: true,
    premium: true,
    created: "2023-04-12T09:30:00Z",
    kdf: { kind: KdfKind.Argon2id, iterations: 3, memoryMib: 64, parallelism: 4 },
    fingerprint: ["lantern", "ripple", "cobalt", "meadow", "falcon"],
    twoFactor: true,
  };
  async profile(): Promise<AccountProfile> {
    await this.wait();
    return structuredClone(this.demoProfile);
  }

  async emailChangeCode(password: string, email: string): Promise<void> {
    this.tfCheck(password);
    this.calls.push(`email:code:${email}`);
  }
  async emailChange(password: string, email: string, code: string): Promise<void> {
    this.tfCheck(password);
    if (code === DEMO_WRONG) throw new Error("err.badTwoFactor");
    this.calls.push(`email:${email}`);
    this.demoProfile = { ...this.demoProfile, email };
  }

  /// The demo's two-step login: the authenticator on, email codes off.
  private tf: TwoFactorStatus = { authenticator: true, email: false, others: [] };
  private tfCheck(password: string) {
    if (password === DEMO_WRONG) throw new Error("err.badPassword");
  }
  async twoFactorStatus(): Promise<TwoFactorStatus> {
    await this.wait();
    return structuredClone(this.tf);
  }
  async authenticatorSetup(password: string) {
    this.tfCheck(password);
    const shown = (v: string) => ({ value: v, drop: () => undefined });
    return { key: shown("JBSWY3DPEHPK3PXP"), otpauth: shown("otpauth://totp/keyward:alex.morgan@acme.example?secret=JBSWY3DPEHPK3PXP&issuer=keyward") };
  }
  async authenticatorEnable(password: string, _key: string, code: string): Promise<TwoFactorStatus> {
    this.tfCheck(password);
    if (code === DEMO_WRONG) throw new Error("err.badTwoFactor");
    this.calls.push("tf:authenticator");
    this.tf = { ...this.tf, authenticator: true };
    return structuredClone(this.tf);
  }
  async emailTwoFactorSetup(password: string) {
    this.tfCheck(password);
    return { email: this.demoProfile.email };
  }
  async emailTwoFactorSend(password: string, email: string): Promise<void> {
    this.tfCheck(password);
    this.calls.push(`tf:send:${email}`);
  }
  async emailTwoFactorEnable(password: string, _email: string, code: string): Promise<TwoFactorStatus> {
    this.tfCheck(password);
    if (code === DEMO_WRONG) throw new Error("err.badTwoFactor");
    this.calls.push("tf:email");
    this.tf = { ...this.tf, email: true };
    return structuredClone(this.tf);
  }
  async twoFactorDisable(password: string, provider: number): Promise<TwoFactorStatus> {
    this.tfCheck(password);
    this.calls.push(`tf:off:${provider}`);
    this.tf = { authenticator: provider === 0 ? false : this.tf.authenticator, email: provider === 1 ? false : this.tf.email, others: this.tf.others.filter((o) => o.provider !== provider) };
    return structuredClone(this.tf);
  }
  async recoveryCode(password: string) {
    this.tfCheck(password);
    return { value: "DEMO-RECO-VERY-CODE", drop: () => undefined };
  }

  /// The demo's browsers: one paired, and one asking while `?pair=1` says so.
  private browsers: BrowserExtensions = {
    paired: [{ key: "demo-paired", words: ["amber", "canyon", "lilac", "orbit", "spruce"], at: 1780000000, expires: 0 }],
    pending: [],
  };
  /// Puts a browser asking to be paired on the demo's list, for `seconds`.
  askToPair(seconds = 300) {
    const now = Math.floor(Date.now() / 1000);
    this.browsers = { ...this.browsers, pending: [{ key: "demo-asking", words: ["harbor", "violet", "maple", "comet", "tundra"], at: now, expires: now + seconds }] };
  }
  async extensions(): Promise<BrowserExtensions> {
    await this.wait();
    return structuredClone(this.browsers);
  }
  async pairExtension(key: string): Promise<BrowserExtensions> {
    const r = this.browsers.pending.find((x) => x.key === key);
    if (!r) throw new Error("this browser is not on the demo's list");
    this.calls.push(`pair:${key}`);
    this.browsers = { paired: [...this.browsers.paired, { ...r, at: Math.floor(Date.now() / 1000), expires: 0 }], pending: this.browsers.pending.filter((x) => x.key !== key) };
    return structuredClone(this.browsers);
  }
  async unpairExtension(key: string): Promise<BrowserExtensions> {
    if (!this.browsers.paired.some((x) => x.key === key)) throw new Error("this browser is not on the demo's list");
    this.calls.push(`unpair:${key}`);
    this.browsers = { ...this.browsers, paired: this.browsers.paired.filter((x) => x.key !== key) };
    return structuredClone(this.browsers);
  }

  async lock(): Promise<void> {
    if (this.state === SessionState.Unlocked) this.state = SessionState.Locked;
    // The members are vault data: read again after the next unlock.
    this.forgetMembers();
    this.emit({ kind: ChangeKind.Session });
  }
  async logout(): Promise<void> {
    this.state = SessionState.LoggedOut;
    this.forgetMembers();
    this.emit({ kind: ChangeKind.Session });
  }
  async sync(): Promise<void> {
    this.emit({ kind: ChangeKind.Catalog });
  }
  async resetSession(): Promise<void> {
    if (this.state !== SessionState.Damaged) throw new Error("err.sessionNotDamaged");
    this.calls.push("resetSession");
    this.state = SessionState.LoggedOut;
    this.emit({ kind: ChangeKind.Session });
  }
  async accounts(): Promise<Account[]> {
    if (!this.caps.accounts) throw new Error("the demo holds one account");
    return [{ id: "demo", email: "alex@acme.example", server: this.server, active: !this.adding, state: this.state }, ...this.others];
  }
  /// The demo stays on its own vault: a switch is recorded and the account
  /// moves in front, its state taken over.
  async switchAccount(id: string): Promise<void> {
    const to = this.others.find((a) => a.id === id);
    if (!to && id !== "demo") throw new Error("err.noSuchAccount");
    this.calls.push(`switch ${id}`);
    this.adding = false;
    this.emit({ kind: ChangeKind.Session });
  }
  async addAccount(): Promise<void> {
    this.calls.push("addAccount");
    this.adding = true;
    this.emit({ kind: ChangeKind.Session });
  }
  async catalog(): Promise<Catalog> {
    await this.wait();
    if (this.state !== SessionState.Unlocked) throw new Error(`the demo vault is ${this.state}`);
    if (this.membersIn) return structuredClone(this.data);
    if (!this.membersTimer)
      this.membersTimer = setTimeout(() => {
        this.membersTimer = null;
        this.membersIn = true;
        this.emit({ kind: ChangeKind.Catalog });
      }, this.opts.slow! * 2);
    return { ...structuredClone(this.data), members: [], membersLoading: true };
  }
  private forgetMembers() {
    if (!this.opts.slow) return;
    if (this.membersTimer) clearTimeout(this.membersTimer);
    this.membersTimer = null;
    this.membersIn = false;
  }
  async contributions(): Promise<Contribution[]> {
    await this.wait();
    return demoContributions();
  }
  async item(id: string): Promise<ItemDetail> {
    await this.wait();
    const it = this.data.items.find((i) => i.id === id);
    if (!it) throw new Error(`no item "${id}"`);
    const saved = this.written?.item(id);
    if (saved) return structuredClone({ ...saved, item: it });
    const ref = (field: Exclude<SecretField, SecretField.Custom>): SecretRef => ({ itemId: id, field });
    const fields: Field[] = [];
    const vis = (key: string, value: string, mono = false, secret: SecretRef | null = null) => fields.push({ key, label: key, value, secret, mono });
    const hidden = (key: string, r: SecretRef) => fields.push({ key, label: key, value: null, secret: r, mono: true });
    if (it.kind === ItemKind.Login) {
      if (it.subtitle) vis("username", it.subtitle, true, ref(SecretField.Username));
      hidden("password", ref(SecretField.Password));
      if (it.hasTotp) hidden("totp", ref(SecretField.Totp));
      if (id === "aws") fields.push({ key: null, label: "Аккаунт", value: "4417 2290 1186", secret: { itemId: id, field: SecretField.Custom, name: "Аккаунт" }, mono: true });
    } else if (it.kind === ItemKind.Card) {
      vis("cardholder", it.orgId ? "Acme Ltd" : "Alex Morgan");
      hidden("cardNumber", ref(SecretField.CardNumber));
      if (it.expires) vis("expiry", `${it.expires.slice(5)} / ${it.expires.slice(0, 4)}`, true);
      hidden("cardCode", ref(SecretField.CardCode));
    } else if (it.kind === ItemKind.Identity) {
      vis("fullName", "Alex Morgan");
      vis("email", it.subtitle ?? "", true);
      vis("company", "Acme");
      fields.push({ key: "passport", label: "passport", value: null, secret: { itemId: id, field: SecretField.Custom, name: "passport" }, mono: true });
      fields.push({ key: "phone", label: "phone", value: null, secret: { itemId: id, field: SecretField.Custom, name: "phone" }, mono: true });
    } else if (it.kind === ItemKind.SshKey) {
      vis("algorithm", "Ed25519");
      vis("fingerprint", (it.subtitle ?? "").split(" · ")[1] ?? "", true);
      hidden("privateKey", ref(SecretField.PrivateKey));
    }
    return { item: it, fields, notes: it.kind === ItemKind.SecureNote ? ref(SecretField.Notes) : null, passkeys: [], passwordHistory: [] };
  }
  /// The demo holds its copy in a field of its own, and answers as the
  /// daemon does by default.
  async copy(ref: SecretRef): Promise<Copied> {
    this.lastCopied = this.written?.value(ref) ?? demoValue(ref);
    return { clearsIn: 30 };
  }
  async reveal(ref: SecretRef): Promise<Revealed> {
    let value: string | null = this.written?.value(ref) ?? demoValue(ref);
    return {
      get value() {
        if (value === null) throw new Error("a revealed value was read after it was dropped");
        return value;
      },
      drop: () => {
        value = null;
      },
    };
  }
  async totp(itemId: string): Promise<Totp> {
    await this.wait();
    const now = Date.now();
    const step = Math.floor(now / 30000);
    const seed = [...itemId].reduce((a, c) => (a * 31 + c.charCodeAt(0)) % 9973, 7);
    const code = String((step * 7919 + seed * 104729) % 1000000).padStart(6, "0");
    return { code, period: 30, remaining: 30 - Math.floor((now / 1000) % 30) };
  }
  private async change(ids: string[], deleted: boolean, what: string) {
    await new Promise((r) => setTimeout(r, 400));
    if (this.failNext === what) {
      this.failNext = null;
      throw new Error(t("err.forbidden"));
    }
    for (const id of ids) {
      const it = this.data.items.find((i) => i.id === id);
      if (!it) throw new Error(`no item "${id}"`);
      it.deleted = deleted;
    }
    this.emit({ kind: ChangeKind.Catalog });
  }
  trash(ids: string[]) {
    return this.change(ids, true, "trash");
  }
  restore(ids: string[]) {
    return this.change(ids, false, "restore");
  }
  /// Changes the catalogue in place and announces it, as a sync would: what
  /// `DemoWrites` saves goes through here.
  mutate(change: (data: Catalog) => void) {
    change(this.data);
    this.emit({ kind: ChangeKind.Catalog });
  }
  async purge(ids: string[]): Promise<void> {
    this.data.items = this.data.items.filter((i) => !ids.includes(i.id));
    this.emit({ kind: ChangeKind.Catalog });
  }
}

export { DEMO_NOW };
