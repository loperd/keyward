// A synthetic vault the size of a real one, for benchmarks, tests and the
// stand's `?synthetic=N`: items spread over personal folders and several
// organisations with their collections and members, password-reuse groups,
// cards that expire, old passwords, SSH keys and a trash. Deterministic: the
// same options give the same catalogue, byte for byte. No secret values.
import { type Catalog, type Collection, type Folder, type Item, ItemKind, type Member, MemberStatus, type Org, OrgRole, Permission, type Policy, PolicyType } from "../model/types";
import { DEMO_NOW } from "../demo";

export type SyntheticOptions = {
  /// How many items, the base's not counted.
  items: number;
  seed?: number;
  /// Personal folders.
  folders?: number;
  /// Organisations; the first is the large one.
  orgs?: number;
  collectionsPerOrg?: number;
  /// Members of the first organisation; the others get a fraction of it.
  members?: number;
  /// A catalogue the synthetic one is added to (the demo, for the stand,
  /// so the demo plugin's nodes still find their items).
  base?: Catalog;
  /// The day the dates are set against.
  now?: Date;
  /// The share of items whose service is one of their own ("GitHub nova12")
  /// rather than one of a few dozen everybody has: a real vault has hundreds
  /// of services, a handful of items each. 0.95 unless said.
  serviceVariety?: number;
};

/// mulberry32: a small, fast, seeded generator.
function rng(seed: number) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return {
    next,
    int: (lo: number, hi: number) => lo + Math.floor(next() * (hi - lo + 1)),
    pick: <T>(xs: readonly T[]): T => {
      if (!xs.length) throw new Error("synthetic: pick from an empty list");
      return xs[Math.floor(next() * xs.length)]!;
    },
    chance: (p: number) => next() < p,
  };
}

const SERVICES = [
  "GitHub", "GitLab", "AWS", "Google", "Slack", "Jira", "Confluence", "Figma", "Notion", "Stripe", "Cloudflare", "PagerDuty",
  "Datadog", "Sentry", "Heroku", "DigitalOcean", "Azure", "Okta", "Zoom", "Dropbox", "Linear", "Vercel", "Netlify", "Twilio",
  "SendGrid", "Mailgun", "HubSpot", "Salesforce", "Zendesk", "Intercom", "Docker Hub", "npm", "PyPI", "Grafana", "Kibana",
  "Почта", "Банк", "Госуслуги", "Хостинг", "Роутер",
];
const ROLES = ["production", "staging", "admin", "billing", "ci bot", "team", "readonly", "backup", "personal", "ops", "on-call", "sandbox"];
const WORDS = ["alpha", "bravo", "delta", "echo", "kilo", "lima", "nova", "orbit", "pixel", "quartz", "river", "sierra", "tango", "vector", "zulu"];
const FIRST = ["Alex", "Priya", "Dana", "Marco", "Lena", "Sam", "Tomás", "Yuki", "Chris", "Olga", "Ivan", "Mei", "Noah", "Ava", "Omar", "Sofia", "Liam", "Zoe", "Ilya", "Nina"];
const LAST = ["Morgan", "Raman", "Whitfield", "Bellini", "Fischer", "Okafor", "Ortega", "Tanaka", "Novak", "Petrova", "Smirnov", "Chen", "Brown", "Garcia", "Haddad", "Rossi", "Kim", "Silva", "Ivanov", "Kowalski"];
const ORG_NAMES = ["Initech", "Umbrella", "Hooli", "Soylent", "Wayne Enterprises", "Stark Industries", "Tyrell", "Cyberdyne"];
const COLLECTION_NAMES = ["Platform", "Finance", "Shared", "Ops", "Marketing", "Sales", "Support", "Security", "Data", "Mobile", "Web", "Infra", "HR", "Legal", "Design"];

const KINDS: [ItemKind, number][] = [
  [ItemKind.Login, 0.72],
  [ItemKind.Card, 0.06],
  [ItemKind.SecureNote, 0.1],
  [ItemKind.Identity, 0.04],
  [ItemKind.SshKey, 0.08],
];

const iso = (now: Date, daysAgo: number) => new Date(now.getTime() - daysAgo * 86_400_000).toISOString();
const month = (now: Date, monthsAhead: number) => {
  const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + monthsAhead, 1));
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
};

export function synthetic(o: SyntheticOptions): Catalog {
  if (!Number.isInteger(o.items) || o.items < 0) throw new Error(`synthetic: items must be a whole number, got ${o.items}`);
  const r = rng(o.seed ?? 1);
  const now = o.now ?? DEMO_NOW;
  const nFolders = o.folders ?? 40;
  const nOrgs = o.orgs ?? 4;
  if (nOrgs > ORG_NAMES.length) throw new Error(`synthetic: at most ${ORG_NAMES.length} organisations`);
  const perOrg = o.collectionsPerOrg ?? 30;
  const bigMembers = o.members ?? 300;
  const variety = o.serviceVariety ?? 0.95;

  const folders: Folder[] = Array.from({ length: nFolders }, (_, i) => ({ id: `sf${i}`, name: `${r.pick(WORDS)} ${i}` }));
  const roles: OrgRole[] = [OrgRole.Owner, OrgRole.Admin, OrgRole.Manager, OrgRole.User];
  const orgs: Org[] = Array.from({ length: nOrgs }, (_, i) => {
    const role = i === 0 ? OrgRole.Owner : r.pick(roles);
    const admin = role === OrgRole.Owner || role === OrgRole.Admin;
    return { id: `so${i}`, name: ORG_NAMES[i]!, role, can: { editOrg: admin, manageMembers: admin, manageCollections: admin || role === OrgRole.Manager } };
  });
  const collections: Collection[] = orgs.flatMap((org, oi) =>
    Array.from({ length: perOrg }, (_, i): Collection => ({ id: `sc${oi}-${i}`, orgId: org.id, name: `${COLLECTION_NAMES[i % COLLECTION_NAMES.length]} ${Math.floor(i / COLLECTION_NAMES.length) + 1}`, readOnly: r.chance(0.1) })),
  );
  const byOrg = new Map(orgs.map((x) => [x.id, collections.filter((c) => c.orgId === x.id)]));

  const members: Member[] = [];
  const perms: Permission[] = [Permission.Manage, Permission.Edit, Permission.Read, Permission.ReadHidden];
  orgs.forEach((org, oi) => {
    const n = oi === 0 ? bigMembers : Math.max(3, Math.round(bigMembers / (oi + 2)));
    const cs = byOrg.get(org.id)!;
    for (let i = 0; i < n; i++) {
      const name = `${r.pick(FIRST)} ${r.pick(LAST)}`;
      const status: MemberStatus = r.chance(0.85) ? MemberStatus.Confirmed : r.chance(0.5) ? MemberStatus.Accepted : MemberStatus.Invited;
      const all = i < 2 || r.chance(0.05);
      const access: Record<string, Permission> = {};
      if (!all) for (let k = r.int(1, Math.min(8, cs.length)); k > 0; k--) access[r.pick(cs).id] = r.pick(perms);
      members.push({
        id: `sm${oi}-${i}`,
        orgId: org.id,
        name: r.chance(0.9) ? name : null,
        email: `${name.toLowerCase().replace(/[^a-z]+/g, ".")}.${i}@${org.name.toLowerCase().replace(/\W+/g, "")}.example`,
        role: i === 0 ? OrgRole.Owner : i === 1 ? OrgRole.Admin : r.pick(roles.slice(2)),
        status,
        twoFactor: status === MemberStatus.Invited ? null : r.chance(0.8),
        accessAll: all,
        access: all ? {} : access,
        isYou: i === 0,
      });
    }
  });
  const policies: Policy[] = orgs.flatMap((org, oi): Policy[] =>
    oi % 2 === 0
      ? [
          { orgId: org.id, type: PolicyType.TwoFactor, enabled: oi === 0 ? false : true, data: {} },
          { orgId: org.id, type: PolicyType.VaultTimeout, enabled: true, data: { minutes: oi === 0 ? 240 : 30 } },
          { orgId: org.id, type: PolicyType.MasterPassword, enabled: true, data: { minLength: 14 } },
        ]
      : [],
  );

  const kindOf = () => {
    let x = r.next();
    for (const [k, p] of KINDS) if ((x -= p) < 0) return k;
    return ItemKind.Login;
  };
  const items: Item[] = [];
  let group = 1_000_000;
  for (let i = 0; i < o.items; i++) {
    const kind = kindOf();
    const common = r.pick(SERVICES);
    const service = variety > 0 && r.chance(variety) ? `${common} ${r.pick(WORDS)}${r.int(1, 99)}` : common;
    // Some names repeat exactly, so slugs take numbers; most say a service.
    const name = r.chance(0.04) ? `${service}` : kind === ItemKind.SshKey ? `id_ed25519 — ${r.pick(WORDS)} ${i}` : `${service} — ${r.pick(ROLES)} ${i}`;
    const personal = r.chance(0.4);
    const org = personal ? null : orgs[Math.min(orgs.length - 1, Math.floor(Math.pow(r.next(), 1.6) * orgs.length))]!;
    const cs = org ? byOrg.get(org.id)! : [];
    const collectionIds = org && cs.length && r.chance(0.97) ? [r.pick(cs).id, ...(r.chance(0.1) ? [r.pick(cs).id] : [])].filter((x, k, a) => a.indexOf(x) === k) : [];
    const revisedDays = r.int(1, 1400);
    const zone = r.pick(["prod", "staging", "dev"]);
    items.push({
      id: `s${i}`,
      name,
      kind,
      subtitle: kind === ItemKind.Login ? `${r.pick(FIRST).toLowerCase()}@${service.toLowerCase().replace(/\W+/g, "")}.example` : kind === ItemKind.Card ? `Visa ·· ${String(r.int(1000, 9999))}` : kind === ItemKind.SshKey ? `Ed25519 · SHA256:${r.pick(WORDS)}${i}` : null,
      folderId: personal && nFolders && r.chance(0.85) ? folders[r.int(0, nFolders - 1)]!.id : null,
      orgId: org ? org.id : null,
      collectionIds,
      uris: kind === ItemKind.Login ? [`https://${service.toLowerCase().replace(/\W+/g, "")}.example/${i}`] : [],
      tags: kind === ItemKind.SshKey ? { "kw-host": `*.${zone}.synthetic.example` } : {},
      hasTotp: kind === ItemKind.Login && r.chance(0.3),
      passkeys: kind === ItemKind.Login && r.chance(0.05) ? 1 : 0,
      favorite: r.chance(0.03),
      deleted: r.chance(0.01),
      reprompt: r.chance(0.04),
      revised: iso(now, revisedDays),
      passwordRevised: kind === ItemKind.Login ? iso(now, revisedDays) : null,
      expires: kind === ItemKind.Card ? month(now, r.int(-6, 36)) : null,
      reused: 0,
      reuseGroup: null,
    });
  }
  // Reuse groups: about 4% of the logins share a password with 1 to 4 others.
  const logins = items.filter((i) => i.kind === ItemKind.Login && !i.deleted);
  for (let k = 0; k < Math.floor(logins.length * 0.012); k++) {
    const size = r.int(2, 5);
    const g = group++;
    const xs: Item[] = [];
    for (let j = 0; j < size; j++) {
      const it = r.pick(logins);
      if (it.reuseGroup === null && !xs.includes(it)) xs.push(it);
    }
    if (xs.length < 2) continue;
    for (const it of xs) {
      it.reuseGroup = g;
      it.reused = xs.length - 1;
    }
  }
  const base = o.base;
  return {
    items: [...(base?.items ?? []), ...items],
    folders: [...(base?.folders ?? []), ...folders],
    orgs: [...(base?.orgs ?? []), ...orgs],
    collections: [...(base?.collections ?? []), ...collections],
    members: [...(base?.members ?? []), ...members],
    policies: [...(base?.policies ?? []), ...policies],
  };
}
