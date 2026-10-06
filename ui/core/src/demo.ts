// A demo vault: the stand's data and the tests' fixture. No secret values —
// the demo backend answers reveals with values of its own, marked "demo-".
// Dates are set against 5 October 2026, the day the stand's screens were
// drawn, so a card's expiry and a password's age read the same in a picture
// and in a test.
import { type Catalog, type Item, OrgRole, MemberStatus, Permission, PolicyType, ItemKind } from "./model/types";

const item = (o: Partial<Item> & Pick<Item, "id" | "name" | "kind">): Item => ({
  subtitle: null,
  folderId: null,
  orgId: null,
  collectionIds: [],
  uris: [],
  tags: {},
  hasTotp: false,
  passkeys: 0,
  favorite: false,
  deleted: false,
  reprompt: false,
  revised: null,
  passwordRevised: null,
  expires: null,
  reused: 0,
  reuseGroup: null,
  ...o,
});

export const DEMO_NOW = new Date("2026-10-05T12:00:00Z");

export const DEMO: Catalog = {
  folders: [
    { id: "work", name: "Work" },
    { id: "home", name: "Дом" },
    { id: "keys", name: "SSH-ключи" },
  ],
  orgs: [
    { id: "acme", name: "Acme", role: OrgRole.Owner, can: { editOrg: true, manageMembers: true, manageCollections: true } },
    { id: "globex", name: "Globex", role: OrgRole.User, can: { editOrg: false, manageMembers: false, manageCollections: false } },
  ],
  collections: [
    { id: "platform", orgId: "acme", name: "Platform", readOnly: false },
    { id: "finance", orgId: "acme", name: "Finance", readOnly: false },
    { id: "shared", orgId: "acme", name: "Shared", readOnly: false },
    { id: "ops", orgId: "globex", name: "Ops", readOnly: false },
  ],
  members: [
    { id: "alex", orgId: "acme", name: "Alex Morgan", email: "alex@acme.example", role: OrgRole.Owner, status: MemberStatus.Confirmed, twoFactor: true, accessAll: true, access: {}, isYou: true },
    { id: "priya", orgId: "acme", name: "Priya Raman", email: "priya@acme.example", role: OrgRole.Admin, status: MemberStatus.Confirmed, twoFactor: true, accessAll: true, access: {}, isYou: false },
    { id: "dana", orgId: "acme", name: "Dana Whitfield", email: "dana@acme.example", role: OrgRole.Manager, status: MemberStatus.Confirmed, twoFactor: true, accessAll: false, access: { platform: Permission.Manage, shared: Permission.Read }, isYou: false },
    { id: "marco", orgId: "acme", name: "Marco Bellini", email: "marco@acme.example", role: OrgRole.Manager, status: MemberStatus.Confirmed, twoFactor: false, accessAll: false, access: { platform: Permission.Edit, shared: Permission.Edit }, isYou: false },
    { id: "lena", orgId: "acme", name: "Lena Fischer", email: "lena@acme.example", role: OrgRole.User, status: MemberStatus.Confirmed, twoFactor: true, accessAll: false, access: { finance: Permission.Edit, shared: Permission.Edit }, isYou: false },
    { id: "sam", orgId: "acme", name: "Sam Okafor", email: "sam@acme.example", role: OrgRole.User, status: MemberStatus.Confirmed, twoFactor: true, accessAll: false, access: { platform: Permission.Read, shared: Permission.Edit }, isYou: false },
    { id: "tomas", orgId: "acme", name: "Tomás Ortega", email: "tomas@acme.example", role: OrgRole.User, status: MemberStatus.Accepted, twoFactor: false, accessAll: false, access: { finance: Permission.ReadHidden, shared: Permission.Read }, isYou: false },
    { id: "yuki", orgId: "acme", name: "Yuki Tanaka", email: "yuki@acme.example", role: OrgRole.User, status: MemberStatus.Invited, twoFactor: null, accessAll: false, access: { shared: Permission.Read }, isYou: false },
    { id: "chris", orgId: "acme", name: "Chris Novak", email: "chris@acme.example", role: OrgRole.User, status: MemberStatus.Invited, twoFactor: null, accessAll: false, access: { shared: Permission.Read }, isYou: false },
  ],
  policies: [
    { orgId: "acme", type: PolicyType.MasterPassword, enabled: true, data: { minLength: 14 } },
    { orgId: "acme", type: PolicyType.TwoFactor, enabled: false, data: {} },
    { orgId: "acme", type: PolicyType.SingleOrg, enabled: true, data: {} },
    { orgId: "acme", type: PolicyType.ResetPassword, enabled: true, data: {} },
    { orgId: "acme", type: PolicyType.PersonalOwnership, enabled: false, data: {} },
    { orgId: "acme", type: PolicyType.VaultTimeout, enabled: true, data: { minutes: 240 } },
  ],
  items: [
    item({ id: "gitlab", name: "GitLab — platform", kind: ItemKind.Login, subtitle: "alex@platform.demo.example", folderId: "work", uris: ["https://gitlab.platform.demo.example"], hasTotp: true, reused: 1, reuseGroup: 1, revised: "2026-05-04T08:12:00Z", passwordRevised: "2026-05-04T08:12:00Z" }),
    item({ id: "aws", name: "AWS — production", kind: ItemKind.Login, subtitle: "alex.morgan", folderId: "work", uris: ["https://console.aws.amazon.com"], hasTotp: true, reused: 1, reuseGroup: 1, revised: "2026-07-01T00:00:00Z", passwordRevised: "2026-07-01T00:00:00Z" }),
    item({ id: "stripe", name: "Stripe — finance", kind: ItemKind.Card, subtitle: "Visa ·· 8812", folderId: "work", expires: "2026-12", revised: "2025-10-01T00:00:00Z" }),
    item({ id: "wifi", name: "Home Wi‑Fi recovery", kind: ItemKind.SecureNote, folderId: "home", revised: "2026-02-01T00:00:00Z" }),
    item({ id: "identity", name: "Alex Morgan", kind: ItemKind.Identity, subtitle: "alex@morgan.example", folderId: "home", revised: "2026-08-01T00:00:00Z" }),
    item({ id: "key-prod", name: "id_ed25519 — production", kind: ItemKind.SshKey, subtitle: "Ed25519 · SHA256:q3Vb…Lx7c", folderId: "keys", tags: { "kw-host": "*.prod.demo.example" }, revised: "2026-01-05T00:00:00Z" }),
    item({ id: "key-staging", name: "id_ed25519 — staging", kind: ItemKind.SshKey, subtitle: "Ed25519 · SHA256:Zk0d…9PmA", folderId: "keys", tags: { "kw-host": "*.staging.demo.example" }, revised: "2026-04-05T00:00:00Z" }),
    item({ id: "github", name: "GitHub — open source", kind: ItemKind.Login, subtitle: "acme-oss-bot", orgId: "acme", collectionIds: ["platform"], uris: ["https://github.com"], passwordRevised: "2024-12-01T10:00:00Z", revised: "2024-12-01T10:00:00Z", hasTotp: true }),
    item({ id: "pv-notes", name: "Platform Vault — recovery notes", kind: ItemKind.SecureNote, orgId: "acme", collectionIds: ["platform"], revised: "2026-06-01T00:00:00Z" }),
    item({ id: "travel", name: "Travel — company card", kind: ItemKind.Card, subtitle: "Mastercard ·· 5530", orgId: "acme", collectionIds: ["finance"], expires: "2026-07", revised: "2025-10-01T00:00:00Z" }),
    item({ id: "billing", name: "AWS — platform billing", kind: ItemKind.Card, subtitle: "Amex ·· 1009", orgId: "acme", collectionIds: ["finance"], expires: "2028-03", reprompt: true, revised: "2026-05-01T00:00:00Z" }),
    item({ id: "cloudflare", name: "Cloudflare — team account", kind: ItemKind.Login, subtitle: "ops@acme.example", orgId: "acme", collectionIds: ["shared"], uris: ["https://dash.cloudflare.com"], passwordRevised: "2025-06-10T00:00:00Z", revised: "2025-06-10T00:00:00Z" }),
    item({ id: "pagerduty", name: "PagerDuty — on-call", kind: ItemKind.Login, subtitle: "alex.m@globex.example", orgId: "globex", collectionIds: ["ops"], uris: ["https://globex.pagerduty.com"], hasTotp: true, revised: "2026-09-01T00:00:00Z", passwordRevised: "2026-09-01T00:00:00Z" }),
  ],
};
