document.documentElement.classList.add("stend");
/// A stand for working on the look.
///
/// The whole application but with made-up data in place of the daemon: it opens
/// in an ordinary browser, which means it can be measured and shown to tools
/// such as design-compiler, which do not look into a Tauri window. It does not
/// reach the build — it is a page of its own, `preview.html`.
import { STAND_TERMINAL } from "./standTerminal";
import { StrictMode } from "react";
import "./styles.css";
import { createRoot } from "react-dom/client";
import { b64, unb64, windowKey } from "./seal";

const LINKS = [
  {
    entry_id: "1",
    entry_name: "Platform Vault — recovery shares",
    addr: "https://vault.demo.example",
    has_role_id: false,
    has_root: true,
    unseal_keys: 3,
  },
  {
    entry_id: "2",
    entry_name: "Vault staging",
    addr: "https://vault.staging.example.com",
    has_role_id: true,
    has_root: false,
    unseal_keys: 5,
  },
];

// The plugins: two built-in and one installed by hand. The list is alive — it
// is edited by `plugin_install`, `plugin_enable` and `plugin_remove` as the
// daemon edits it — or installing and removing could not be tried on the
// stand.
type StendManifest = {
  id: string;
  title: string;
  icon: string;
  section: boolean;
  needs_unlocked: boolean;
  version: string;
  description: string;
  origin: "builtin" | "external";
  enabled: boolean;
  permissions: string[];
  /// The plugin decides whether its section applies.
  probe?: boolean;
  /// The package was taken past the catalogue: there is no signature and no
  /// fingerprint to check against.
  unverified?: boolean;
  /// What was added to the rights by an update.
  added_permissions?: string[];
};

const PLUGINS: StendManifest[] = [
  {
    id: "hashicorp",
    title: "Vault",
    icon: "vault",
    section: true,
    needs_unlocked: true,
    version: "0.1.0",
    description: "Connections to HashiCorp Vault: handing out access, policies, engines and secrets.",
    origin: "builtin",
    enabled: true,
    permissions: ["entries", "items", "items_write", "secrets", "notices", "network"],
  },
  {
    id: "ssh",
    title: "Routes",
    icon: "route",
    section: true,
    needs_unlocked: true,
    version: "0.1.0",
    description: "keyward's ssh agent: keys from the vault, host-to-key routes, signing on request.",
    origin: "builtin",
    enabled: true,
    permissions: ["entries", "items_write", "notices"],
  },
  {
    id: "vaultwarden",
    title: "Vaultwarden",
    icon: "shield",
    section: true,
    needs_unlocked: true,
    version: "0.1.0",
    description: "The server's admin panel.",
    origin: "builtin",
    enabled: true,
    permissions: ["keychain", "network"],
    probe: true,
  },
  {
    id: "hello",
    title: "Hello",
    icon: "note",
    section: true,
    needs_unlocked: false,
    version: "1.0.0",
    description: "Shows that plugins work: answers \"state\" and lists the ssh keys.",
    origin: "external",
    enabled: false,
    permissions: ["entries", "notices"],
  },
];

// The catalogue: what the daemon gives out for `PluginCatalog`. The fields
// about installation (`installed`, `update`) it works out itself, comparing the
// catalogue with the disk — the stand counts them the same way, from the living
// `PLUGINS` list, or after "Install" was pressed the card would go on offering
// the installation.
type StendEntry = {
  id: string;
  title: string;
  description: string;
  icon: string;
  homepage: string;
  source: string;
  url: string;
  version: string;
  permissions: string[];
  size: number;
  publisher: string;
  signed?: boolean;
  /// The five words of the publisher key's fingerprint — as for an account's.
  fingerprint?: string[];
  revoked?: boolean;
  reason?: string;
};

const SOURCES = ["https://plugins.keyward.app/index.json"];

// The trusted publishers: ours is built in, a foreign one is added by a person
// after checking the five words. The list is alive — `plugin_trust` adds to it,
// and the card then changes its action to "Install" by itself.
const TRUSTED = new Set(["keyward"]);

const CATALOG: StendEntry[] = [
  {
    id: "hello",
    title: "Hello",
    description: "Shows that plugins work: answers \"state\" and lists the ssh keys.",
    icon: "note",
    homepage: "https://git.example.com/keyward-plugins/hello",
    source: "https://plugins.keyward.app/index.json",
    url: "https://plugins.keyward.app/hello/1.2.0/hello-1.2.0.tar.gz",
    version: "1.2.0",
    // The update asks for more than is installed: `network` has been added —
    // a plugin like that comes up switched off, and the consent is asked
    // afresh.
    permissions: ["entries", "notices", "network"],
    size: 4096,
    publisher: "keyward",
    signed: true,
  },
  {
    id: "weather",
    title: "Weather",
    description: "Puts the weather into a note and reminds you of an umbrella. Goes to the network.",
    icon: "globe",
    homepage: "https://git.example.com/keyward-plugins/weather",
    source: "https://plugins.keyward.app/index.json",
    url: "https://plugins.keyward.app/weather/1.2.0/weather-1.2.0.tar.gz",
    version: "1.2.0",
    permissions: ["items", "items_write", "notices", "network"],
    size: 182_400,
    publisher: "keyward",
    signed: true,
  },
  {
    id: "totp-import",
    title: "TOTP Import",
    description: "Moves one-time codes from otpauth links and QR codes into the vault's items.",
    icon: "clock",
    homepage: "https://git.example.com/keyward-plugins/totp-import",
    source: "https://plugins.keyward.app/index.json",
    url: "https://plugins.keyward.app/totp-import/0.4.1/totp-import-0.4.1.tar.gz",
    version: "0.4.1",
    permissions: ["items", "items_write"],
    size: 1_310_720,
    // A foreign publisher: until their key is recognised the card offers not
    // the installation but a conversation about the key.
    publisher: "tsvetkov",
    signed: true,
    fingerprint: ["dosage", "hurdle", "premises", "tinwork", "amaretto"],
  },
  {
    id: "clipwatch",
    title: "Clipwatch",
    description: "Watched the clipboard and cleared it a minute after a copy.",
    icon: "copy",
    homepage: "https://git.example.com/keyward-plugins/clipwatch",
    source: "https://plugins.keyward.app/index.json",
    url: "https://plugins.keyward.app/clipwatch/0.2.0/clipwatch-0.2.0.tar.gz",
    version: "0.2.0",
    permissions: ["items", "notices"],
    size: 20_480,
    publisher: "keyward",
    signed: true,
    revoked: true,
    reason: "the publisher's key has leaked",
  },
];

// `?catalog=stale` — the catalogue did not answer and the list came from the
// cache; `?catalog=empty` — not one source got through and there is no cache.
// Refreshing the list "freshens" the cache: the line about the cache has to be
// not only shown but also taken away.
const CATALOG_MODE = new URLSearchParams(location.search).get("catalog");
let catalogStale = CATALOG_MODE === "stale";

const CANNED: Record<string, unknown> = {
  daemon_status: {
    version: "0.1.0",
    source: "vault",
    pending_edits: new URLSearchParams(location.search).has("edits") ? 3 : 0,
    vault: { state: "unlocked", email: "alex@demo.example", server: "https://vault.demo.example", entries: 42, tagged: 7 },
    biometric: true,
    pin: false,
  },
  vault_accounts: {
    accounts: [
      {
        account: { id: "a", email: "alex@demo.example", base_url: "https://vault.demo.example", identity_url: null },
        state: { state: "unlocked", email: "alex@demo.example", server: "https://vault.demo.example", entries: 42, tagged: 7 },
        biometric: true,
        pin: false,
      },
    ],
    active: "a",
  },
  vault_items: {
    items: [
      {
        id: "i1",
        name: "GitLab — platform",
        kind: "login",
        subtitle: "alex@demo.example",
        folder_id: "f1",
        folder_name: "Work",
        org_id: null,
        uris: ["https://gitlab.demo.example"],
        tags: {},
        has_totp: true,
        passkeys: 2,
        favorite: true,
        deleted: false,
        org_name: null,
        collection_ids: [],
        reprompt: false,
      },
      {
        id: "i2",
        name: "Cloudflare — team account",
        kind: "login",
        subtitle: "alex@demo.example",
        folder_id: "f1",
        folder_name: "Work",
        org_id: null,
        uris: ["https://dash.cloudflare.com"],
        tags: {},
        has_totp: true,
        passkeys: 0,
        favorite: true,
        deleted: false,
        org_name: null,
        collection_ids: [],
        reprompt: true,
      },
      {
        id: "i3",
        name: "id_ed25519 — production",
        kind: "ssh_key",
        subtitle: "git.prod.demo.example · *.prod.demo.example",
        folder_id: "f1",
        folder_name: "Work",
        org_id: null,
        uris: [],
        tags: {},
        has_totp: false,
        passkeys: 0,
        favorite: false,
        deleted: false,
        org_name: null,
        collection_ids: [],
        reprompt: false,
      },
      {
        id: "i4",
        name: "AWS — production",
        kind: "login",
        subtitle: "alex@demo.example",
        folder_id: "f1",
        folder_name: "Work",
        org_id: null,
        uris: ["https://console.aws.amazon.com"],
        tags: {},
        has_totp: true,
        passkeys: 0,
        favorite: false,
        deleted: false,
        org_name: null,
        collection_ids: [],
        reprompt: false,
      },
      {
        id: "i5",
        name: "Platform Vault — recovery notes",
        kind: "secure_note",
        subtitle: null,
        folder_id: null,
        folder_name: null,
        org_id: null,
        uris: [],
        tags: {},
        has_totp: false,
        favorite: false,
        deleted: false,
        org_name: null,
        collection_ids: [],
        reprompt: false,
      },
      {
        id: "i6",
        name: "Stripe — finance",
        kind: "card",
        subtitle: "•••• 4242 · expires 09/29",
        card_brand: "Visa",
        folder_id: "f2",
        folder_name: "Personal",
        org_id: null,
        uris: ["https://dashboard.stripe.com"],
        tags: { owner: "Finance" },
        has_totp: false,
        passkeys: 0,
        favorite: false,
        deleted: false,
        org_name: null,
        collection_ids: [],
        reprompt: true,
      },
      {
        id: "i7",
        name: "Alex Morgan",
        kind: "identity",
        subtitle: "Personal identity",
        folder_id: "f2",
        folder_name: "Personal",
        org_id: null,
        uris: [],
        tags: {},
        has_totp: false,
        passkeys: 0,
        favorite: false,
        deleted: false,
        org_name: null,
        collection_ids: [],
        reprompt: false,
      },
      {
        id: "i8",
        name: "GitHub — open source",
        kind: "login",
        subtitle: "alex-demo",
        folder_id: "f1",
        folder_name: "Work",
        org_id: "o1",
        uris: ["https://github.com"],
        tags: { team: "Platform" },
        has_totp: true,
        passkeys: 1,
        favorite: true,
        deleted: false,
        org_name: "Acme",
        collection_ids: ["c1"],
        reprompt: false,
      },
      {
        id: "i9",
        name: "id_ed25519 — staging",
        kind: "ssh_key",
        subtitle: "*.staging.demo.example",
        folder_id: "f1",
        folder_name: "Work",
        org_id: null,
        uris: [],
        tags: { environment: "staging" },
        has_totp: false,
        passkeys: 0,
        favorite: false,
        deleted: false,
        org_name: null,
        collection_ids: [],
        reprompt: false,
      },
      {
        id: "i10",
        name: "Home Wi‑Fi recovery",
        kind: "secure_note",
        subtitle: "router, ISP and recovery details",
        folder_id: "f2",
        folder_name: "Personal",
        org_id: null,
        uris: [],
        tags: {},
        has_totp: false,
        passkeys: 0,
        favorite: false,
        deleted: false,
        org_name: null,
        collection_ids: [],
        reprompt: true,
      },
      {
        id: "i11",
        name: "AWS — platform billing",
        kind: "card",
        subtitle: "•••• 4444 · expires 06/30",
        card_brand: "Mastercard",
        folder_id: "f1",
        folder_name: "Work",
        org_id: "o1",
        uris: ["https://aws.amazon.com"],
        tags: { owner: "Platform" },
        has_totp: false,
        passkeys: 0,
        favorite: false,
        deleted: false,
        org_name: "Acme",
        collection_ids: ["c1"],
        reprompt: true,
      },
      {
        id: "i12",
        name: "Travel — company card",
        kind: "card",
        subtitle: "•••• 0005 · expires 11/28",
        card_brand: "American Express",
        folder_id: "f1",
        folder_name: "Work",
        org_id: "o1",
        uris: [],
        tags: { owner: "Operations" },
        has_totp: false,
        passkeys: 0,
        favorite: false,
        deleted: false,
        org_name: "Acme",
        collection_ids: ["c1"],
        reprompt: true,
      },
    ],
    folders: [{ id: "f1", name: "Work", count: 8 }, { id: "f2", name: "Personal", count: 4 }],
    counts: [
      ["login", 4],
      ["card", 3],
      ["identity", 1],
      ["note", 2],
      ["ssh_key", 2],
    ],
    unfiled: 0,
    orgs: [
      { id: "o1", name: "Acme", role: "owner", count: 0, can: { edit_org: true, manage_users: true, create_collections: true, edit_collections: true, delete_collections: true, assignable_roles: ["user", "manager", "admin", "owner"] } },
      { id: "o2", name: "Globex", role: "user", count: 0, can: { edit_org: false, manage_users: false, create_collections: false, edit_collections: false, delete_collections: false, assignable_roles: [] } },
    ],
    collections: [{ id: "c1", name: "Shared", org_id: "o1", read_only: false, count: 0 }],
    trash: 0,
    favorites: 3,
  },
  pending_edits: [
    { id: "e1", account_id: "a", entry_id: "i1", entry_name: "GitLab — platform", created_at: "@1790670000", changed: [{ label: "field.password", had_value: true, has_value: true }], state: { state: "pending", attempts: 2, last_error: null } },
    { id: "e2", account_id: "", entry_id: "", entry_name: "", created_at: "", changed: [], state: { state: "pending", attempts: 0, last_error: null }, locked: true },
    { id: "e3", account_id: "", entry_id: "", entry_name: "", created_at: "", changed: [], state: { state: "pending", attempts: 0, last_error: null }, damaged: true },
    { id: "e4", account_id: "a", entry_id: "i2", entry_name: "webauthn.io", created_at: "@1790660000", changed: [{ label: "field.passkey", had_value: true, has_value: true }], state: { state: "pushed" } },
  ],
  get_settings: {
    lock_timeout: { kind: "minutes", minutes: 15 },
    lock_action: "lock",
    touch_id_on_launch: true,
    touch_id_for_secrets: false,
    clipboard_clear_seconds: 30,
    biometric_grace_seconds: 300,
    show_website_icons: true,
    hide_on_copy: false,
    keep_in_tray: true,
    keep_in_dock: false,
    allow_screen_capture: false,
    start_on_login: true,
    theme: "system",
    language: "auto",
  },
  apply_window_prefs: null,
  // The account: a profile with the five words of the fingerprint, the second
  // factor, the devices, the export — everything the settings screen has to
  // show.
  account_profile: {
    user_id: "6f1c2d0e-3a4b-4c5d-8e9f-0a1b2c3d4e5f",
    email: "you@example.com",
    name: "Alex Morgan",
    avatar_color: "#33ccff",
    master_password_hint: "as usual, only longer",
    email_verified: true,
    premium: true,
    creation_date: "2023-11-14T09:12:00Z",
    kdf: { kind: "argon2id", iterations: 3, memory_mib: 64, parallelism: 4 },
    fingerprint: ["alkaline", "tumbling", "crouton", "flyover", "unsavory"],
    two_factor_enabled: true,
  },
  two_factor_status: { authenticator: false, email: true, others: [{ provider: 7, name: "WebAuthn" }] },
  two_factor_authenticator_setup: {
    key: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
    otpauth: "otpauth://totp/Bitwarden:you%40example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Bitwarden",
    enabled: false,
  },
  two_factor_email_setup: { email: "you@example.com", enabled: false },
  two_factor_email_send: null,
  two_factor_recovery_code: "7QJK-3XPM-9RTW-2LZD-8BNF-4HCV-6GSY-1DEA",
  devices: [
    { id: "d1", name: "MacBook Pro", kind: "desktop", identifier: "kw-1", created: "2026-01-10T10:00:00Z", last_active: "2026-09-09T08:41:00Z", current: true },
    { id: "d2", name: "Firefox", kind: "browser extension", identifier: "ff-2", created: "2025-03-02T10:00:00Z", last_active: "2026-09-08T19:12:00Z", current: false },
    { id: "d3", name: "iPhone", kind: "mobile", identifier: "ios-3", created: "2024-07-21T10:00:00Z", last_active: "2026-09-01T07:00:00Z", current: false },
    { id: "d4", name: "rbw", kind: "cli", identifier: "cli-4", created: "2026-05-05T10:00:00Z", last_active: null, current: false },
  ],
  export_vault: "/Users/you/Downloads/bitwarden_export_20260909120000.json",
  account_set_profile: null,
  account_email_token: null,
  item_detail: {
    id: "i1",
    name: "GitLab — platform",
    kind: "login",
    folder_name: "Work",
    passkeys: [
      { credential_id: "cred-1", rp_id: "gitlab.demo.example", rp_name: "GitLab", user_name: "alex@demo.example", user_display_name: "Alex", key_algorithm: "ECDSA", key_curve: "P-256", discoverable: true, counter: 14, created: "2026-03-02T10:00:00Z", last_used: "2026-09-29T08:38:40Z" },
    ],
    password_history: [
      { index: 0, last_used: "2026-09-12T08:14:00Z" },
      { index: 1, last_used: "2026-06-03T17:40:00Z" },
    ],
    uris: ["https://gitlab.demo.example"],
    reprompt: false,
    deleted: false,
    fields: [
      { key: "username", label: "Login", value: "alex@demo.example", secret: null, hidden: false, mono: false, extra: [] },
      { key: "password", label: "Password", value: null, secret: "password", hidden: true, mono: true, extra: [] },
      { key: "totp", label: "Authenticator key", value: null, secret: "totp", hidden: true, mono: true, extra: [] },
    ],
    custom: [
      { name: "environment", value: "production", hidden: false, kind: 0, linked_id: null },
      { name: "recovery", value: null, hidden: true, kind: 1, linked_id: null },
    ],
  },
  recent_items: ["i1"],
  generate_password: "demo-generated-16",
  copy_text: 30,
  biometric_state: { available: true, problem: null, last_failure: null },
  note_fields: ["share-1", "share-2", "share-3", "share-4", "share-5", "root-token"],
};

// Preview-only stand-ins for the vault icon service. In the application these
// arrive as data URLs from Bitwarden/Vaultwarden's own icon endpoint; the
// stand must never ask a third party about a made-up person's sites.
function demoFavicon(domain: string): string {
  const marks: Record<string, [string, string]> = {
    "gitlab.demo.example": ["#fc6d26", "GL"],
    "dash.cloudflare.com": ["#f38020", "CF"],
    "console.aws.amazon.com": ["#ff9900", "AWS"],
    "github.com": ["#24292f", "GH"],
  };
  const [color, letters] = marks[domain] ?? ["#3b82f6", domain.slice(0, 2).toUpperCase()];
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="${color}"/><text x="16" y="20" text-anchor="middle" fill="white" font-family="Arial,sans-serif" font-size="${letters.length > 2 ? 8 : 11}" font-weight="700">${letters}</text></svg>`;
  return `data:image/svg+xml,${encodeURIComponent(svg)}`;
}

/** Give every list row its own coherent card. The production bridge returns a
 * detail by `entryId`; the stand has to obey that contract too, otherwise a
 * product screenshot lies about the interaction. */
function previewItemDetail(entryId: string): unknown {
  const catalog = CANNED.vault_items as { items: Array<{ id: string; name: string; kind: string; folder_name: string | null; uris: string[]; favorite: boolean; reprompt: boolean; has_totp: boolean; passkeys: number; subtitle: string | null; card_brand?: string | null }> };
  const item = catalog.items.find((v) => v.id === entryId);
  if (!item || entryId === "i1") return CANNED.item_detail;

  const base = {
    id: item.id, name: item.name, kind: item.kind, folder_name: item.folder_name,
    uris: item.uris, passkeys: [], reprompt: item.reprompt, deleted: false, favorite: item.favorite, custom: [],
  };
  if (item.kind === "login") {
    return {
      ...base,
      fields: [
        { key: "username", label: "username", value: item.subtitle ?? "alex@demo.example", secret: null, hidden: false, mono: false, extra: [] },
        { key: "password", label: "password", value: null, secret: "password", hidden: true, mono: true, extra: [] },
        ...(item.has_totp ? [{ key: "totp", label: "totp", value: null, secret: "totp", hidden: true, mono: true, extra: [] }] : []),
      ],
      passkeys: Array.from({ length: item.passkeys }, (_, n) => ({ credential_id: `${item.id}-${n}`, rp_id: item.uris[0]?.replace(/^https:\/\//, "") ?? "demo.example", rp_name: null, user_name: item.subtitle, user_display_name: "Alex", key_algorithm: "ECDSA", key_curve: "P-256", discoverable: true, counter: n + 1, created: "2026-09-01T10:00:00Z", last_used: n === 0 ? "2026-09-28T19:05:00Z" : null })),
    };
  }
  if (item.kind === "card") {
    const masks: Record<string, string> = { i6: "424242 ···· 4242", i11: "555555 ···· 4444", i12: "378282 ···· 0005" };
    return {
      ...base,
      fields: [
        { key: "cardholder", label: "cardholder", value: "ALEX MORGAN", secret: null, hidden: false, mono: false, extra: [] },
        { key: "brand", label: "brand", value: item.card_brand ?? "Other", secret: null, hidden: false, mono: false, extra: [] },
        { key: "expiry", label: "expiry", value: item.id === "i12" ? "11/2028" : "06/2030", secret: null, hidden: false, mono: true, extra: [] },
        { key: "cardNumber", label: "cardNumber", value: masks[item.id] ?? "•••• ···· 0000", secret: "card_number", hidden: true, mono: true, extra: [] },
        { key: "cardCode", label: "cardCode", value: null, secret: "card_code", hidden: true, mono: true, extra: [] },
      ],
    };
  }
  if (item.kind === "identity") {
    return { ...base, fields: [
      { key: "fullName", label: "fullName", value: "Alex Morgan", secret: null, hidden: false, mono: false, extra: [] },
      { key: "email", label: "email", value: "alex@demo.example", secret: "username", hidden: false, mono: false, extra: [] },
      { key: "phone", label: "phone", value: "+1 202 555 0148", secret: "username", hidden: false, mono: true, extra: [] },
      { key: "address1", label: "address1", value: "42 Demo Street", secret: null, hidden: false, mono: false, extra: [] },
    ] };
  }
  if (item.kind === "ssh_key") {
    return { ...base, fields: [
      { key: "fingerprint", label: "fingerprint", value: "SHA256:demo-preview-key", secret: null, hidden: false, mono: true, extra: [] },
      { key: "publicKey", label: "publicKey", value: "ssh-ed25519 AAAA… alex@demo.example", secret: null, hidden: false, mono: true, extra: [] },
      { key: "privateKey", label: "privateKey", value: null, secret: "private_key", hidden: true, mono: true, extra: [] },
    ], custom: [{ name: "kw-host", value: item.subtitle ?? "*.demo.example", hidden: false, kind: 0, linked_id: null }] };
  }
  return { ...base, fields: [{ key: "notes", label: "notes", value: null, secret: "notes", hidden: true, mono: false, extra: [] }] };
}

// The commands whose answer depends on the arguments: kv secrets by path.
const SECRET_FIELDS: Record<string, string> = {
  ADMIN_PANEL_ENABLED: "true",
  ADMIN_TOKEN: "demo-admin-token",
  ALLOW_OAUTH_ORIGIN: "https",
  ANTHROPIC_API_KEY: "",
  DATABASE_URI: "postgresql://jira_metrics:demo-password@pg-primary.prod.svc.cluster.local:5432/jira_metrics?sslmode=require",
  ENCRYPTION_KEY: "demo-encryption-key",
  JWT_SECRET: "demo-jwt-secret",
  NATS_URL: "nats://nats.prod.svc.cluster.local:4222",
  OAUTH_GOOGLE_CLIENT_ID: "demo-client-id.apps.googleusercontent.com",
  OAUTH_GOOGLE_CLIENT_SECRET: "demo-client-secret",
  REDIS_URL: "redis://:demo-password@redis.prod.svc.cluster.local:6379/0",
};
const UNLOCKED = (CANNED.daemon_status as { vault: unknown }).vault;
const loginDone = () => ({ kind: "done", state: UNLOCKED });
const DYNAMIC: Record<string, (args: Record<string, unknown>) => unknown> = {
  // The stand remembers the avatar's colour: the accent is painted from it,
  // and without that a change of accent could not be tried by pressing.
  account_set_avatar: (a) => {
    (CANNED.account_profile as { avatar_color: string | null }).avatar_color = (a.color as string) ?? null;
    return null;
  },
  // The answers that count as a login: on the stand everything succeeds at
  // once; `?twofactor=1` makes them ask for a second factor, so that this step
  // can be shown too.
  account_change_password: () =>
    new URLSearchParams(location.search).has("twofactor")
      ? { kind: "two_factor", providers: [{ id: 0, name: "Authenticator", prompt: "", kind: "code" }, { id: 1, name: "Email", prompt: "", kind: "email_code" }] }
      : loginDone(),
  account_change_email: () => loginDone(),
  account_change_kdf: () => loginDone(),
  account_deauthorize: () => loginDone(),
  account_delete: () => UNLOCKED,
  account_purge: () => UNLOCKED,
  vault_login_two_factor: () => UNLOCKED,
  two_factor_authenticator_enable: () => ({ authenticator: true, email: false, others: [] }),
  two_factor_email_enable: () => ({ authenticator: true, email: true, others: [] }),
  two_factor_disable: ({ provider }) => ({ authenticator: provider !== 0, email: false, others: provider === 7 ? [] : [{ provider: 7, name: "WebAuthn" }] }),
  pin_set: () => UNLOCKED,
  ssh_key_draft: () => ({ id: "demo-draft", public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDEMOdemoDEMOdemoDEMOdemoDEMOdemoDEMOdemo demo", fingerprint: "SHA256:demo-fingerprint", algorithm: "ssh-ed25519" }),
  copy_ssh_draft: () => 30,
  generator_history: () => ({ made: [16, 16, 20], taken: [16] }),
  copy_generated: () => 30,
  reveal_generated: () => "demo-history-16",
  // Demo values only: the stand has no vault.
  reveal_secret: ({ field }) =>
    field === "username" ? "alex@demo.example" : field === "totp" ? "482913" : field === "totp_secret" ? "demo-totp-secret" : field === "notes" ? "" : "demo-password",
  regenerate_password: ({ entryId }) => ({ id: "e1", account_id: "a", entry_id: entryId, entry_name: "demo", created_at: "@0", changed: [{ label: "field.password", had_value: true, has_value: true }], state: { state: "pushed" } }),
  pin_clear: () => UNLOCKED,
  pin_unlock: () => UNLOCKED,
  // Kept, as the daemon keeps them: the next get_settings sees the change.
  set_settings: ({ settings }) => ({ ...Object.assign(CANNED.get_settings as object, settings) }),
  // Installing, consenting and removing — the whole path, so that it can be
  // clicked through without a daemon. There is no system dialogue in a browser:
  // the stand gives back a path as if a person had chosen it.
  // A copy rather than the list itself: React compares by reference, and a
  // mutation in place would redraw neither the rail nor the settings.
  plugins: () => PLUGINS.map((p) => ({ ...p })),
  plugin_pick: ({ archive }) => (archive ? "/Users/you/Downloads/weather-1.2.0.tar.gz" : "/Users/you/plugins/weather"),
  // The catalogue: the entries are the daemon's, but `installed`/`update` are
  // counted from the living list — that way a card turns into "Installed" by
  // itself, and "Update" disappears when a new version arrives.
  plugin_catalog: ({ refresh }) => {
    if (refresh) catalogStale = false;
    if (CATALOG_MODE === "empty") return [];
    return CATALOG.map((e) => {
      const have = PLUGINS.find((p) => p.id === e.id);
      return {
        ...e,
        installed: Boolean(have),
        installed_version: have?.version ?? null,
        update: Boolean(have && have.version !== e.version),
        trusted: TRUSTED.has(e.publisher),
        ...(catalogStale ? { stale: true } : {}),
      };
    });
  },
  plugin_sources: ({ set }) => {
    if (Array.isArray(set)) SOURCES.splice(0, SOURCES.length, ...(set as string[]));
    return [...SOURCES];
  },
  plugin_trust: ({ publisher }) => {
    TRUSTED.add(String(publisher));
    return null;
  },
  plugin_install: ({ path }) => {
    const where = String(path ?? "");
    // From the catalogue the manifest is assembled from the entry; an address
    // typed in by hand has nothing to check against, and the daemon marks such
    // a package `unverified`.
    const entry = CATALOG.find((e) => e.url === where || e.id === where);
    const typed = !entry && where.startsWith("https://");
    // An update that asked for more than before comes up switched off and
    // carries the list of what was added: the consent is asked afresh.
    const before = entry ? PLUGINS.find((p) => p.id === entry.id)?.permissions : undefined;
    const added = entry && before ? entry.permissions.filter((p) => !before.includes(p)) : [];
    const fresh: StendManifest = entry
      ? {
          id: entry.id,
          title: entry.title,
          icon: entry.icon,
          section: true,
          needs_unlocked: false,
          version: entry.version,
          description: entry.description,
          origin: "external",
          enabled: false,
          permissions: entry.permissions,
          ...(added.length > 0 ? { added_permissions: added } : {}),
        }
      : {
          id: "weather",
          title: "Weather",
          icon: "globe",
          section: true,
          needs_unlocked: false,
          version: "1.2.0",
          description: "Puts the weather into a note and reminds you of an umbrella. Goes to the network.",
          origin: "external",
          enabled: false,
          permissions: ["items", "items_write", "notices", "network"],
          ...(typed ? { unverified: true } : {}),
        };
    const at = PLUGINS.findIndex((p) => p.id === fresh.id);
    if (at === -1) PLUGINS.push(fresh);
    else PLUGINS[at] = fresh;
    return fresh;
  },
  plugin_enable: ({ id, on }) => {
    const found = PLUGINS.find((p) => p.id === id);
    if (found) found.enabled = Boolean(on);
    return null;
  },
  plugin_remove: ({ id }) => {
    const at = PLUGINS.findIndex((p) => p.id === id);
    if (at !== -1) PLUGINS.splice(at, 1);
    return null;
  },
};

// ── The plugins ──────────────────────────────────────────────────────────
// The daemon gives out the sections' manifests and one `plugin_call` envelope
// for every operation; the stand repeats that by dispatching on the plugin's
// name and the operation.

const HEALTH = { initialized: true, sealed: false, standby: false, version: "1.21.2" };
const SEAL = { type: "shamir", initialized: true, sealed: false, t: 3, n: 5, progress: 0, version: "1.21.2" };
const ISSUED = [
  {
    accessor: "hvs.CAESIJ7pQ",
    recipient: "agent",
    policies: ["kv-read"],
    ttl_seconds: 300,
    num_uses: 1,
    note: "the build agent",
    created_at: Math.floor(Date.now() / 1000) - 120,
    wrapped: true,
    state: { state: "active" },
  },
  {
    accessor: "hvs.CAESIL2ma",
    recipient: "person",
    policies: ["kv-read", "pki-issue"],
    ttl_seconds: 3600,
    num_uses: 0,
    note: "a contractor",
    created_at: Math.floor(Date.now() / 1000) - 7200,
    wrapped: false,
    state: { state: "expired" },
  },
  ...Array.from({ length: 45 }, (_, i) => ({
    accessor: `acc${i}`,
    recipient: (["agent", "person", "me"] as const)[i % 3],
    policies: i % 4 === 0 ? ["keyward-policy-admin"] : ["billing-secrets"],
    ttl_seconds: 900,
    num_uses: i % 5 === 0 ? 6 : 0,
    note: i % 3 === 0 ? `deploy #${i}` : "",
    created_at: Math.floor(Date.now() / 1000) - i * 3600,
    wrapped: i % 2 === 0,
    state: { state: i < 3 ? "active" : i % 7 === 0 ? "revoked" : "expired" },
  })),
];

const ROOTS = [
  {
    entry_id: "r1",
    addr: "https://vault.example.com",
    issued_at: Math.floor(Date.now() / 1000) - 3600 * 6,
    info: { accessor: "hvs.rootAccessor123", policies: ["root"], ttl_seconds: 0, num_uses: 0, display_name: "root" },
  },
];

const POLICIES = ["default", "kv-read", "pki-issue", "root"];
const MOUNTS = [
  { path: "secret", kind: "kv", description: "key/value", kv2: true, accessor: "kv_9a1b2c3d", default_lease_ttl: 0, max_lease_ttl: 0, auth: false },
  { path: "pki", kind: "pki", description: "certificates", kv2: false, accessor: "pki_44f0e1", default_lease_ttl: 3600, max_lease_ttl: 2764800, auth: false },
  { path: "legacy", kind: "kv", description: "the old kv", kv2: false, accessor: "kv_00ff11", default_lease_ttl: 0, max_lease_ttl: 0, auth: false },
  { path: "cubbyhole", kind: "cubbyhole", description: "per-token private secret storage", kv2: false, accessor: "cubbyhole_1", default_lease_ttl: 0, max_lease_ttl: 0, auth: false },
];
const AUTH_MOUNTS = [
  { path: "auth/token", kind: "token", description: "token based credentials", kv2: false, accessor: "auth_token_1", default_lease_ttl: 0, max_lease_ttl: 0, auth: true },
  { path: "auth/approle", kind: "approle", description: "", kv2: false, accessor: "auth_approle_2", default_lease_ttl: 0, max_lease_ttl: 0, auth: true },
  { path: "auth/kubernetes", kind: "kubernetes", description: "k3s-vps", kv2: false, accessor: "auth_k8s_3", default_lease_ttl: 0, max_lease_ttl: 0, auth: true },
];
const POLICY = { name: "kv-read", rules: 'path "secret/data/*" {\n  capabilities = ["read", "list"]\n}\n' };


const HASHICORP_SETTINGS = { active: "1", expiry_notices: true };

const SSH_KEYS = [
  { id: "i3", name: "id_ed25519 — production", hosts: "git.prod.demo.example, *.prod.demo.example", user: "deploy", port: "" },
  { id: "i9", name: "id_ed25519 — staging", hosts: "*.staging.demo.example", user: "ubuntu", port: "2222" },
  { id: "k3", name: "break-glass key", hosts: "", user: "", port: "" },
  { id: "k7", name: "legacy-rsa", hosts: "admin@old.demo.example", user: "", port: "" },
];
const SSH_SETTINGS = { agent_enabled: true, ask: "never", shared_socket: false, health_minutes: 30 };
const SSH_SNIPPET = [
  "Host *.prod.demo.example",
  "  IdentityAgent ~/.keyward/s/i3.sock",
  "",
  "Host git.example.com",
  "  IdentityAgent ~/.keyward/s/i9.sock",
].join("\n");

const secretMeta = (a: Record<string, unknown>) => PLUGIN_OPS.hashicorp.secret_meta(a);

const PLUGIN_OPS: Record<string, Record<string, (p: Record<string, unknown>) => unknown>> = {
  vaultwarden: {
    available: () => ({ available: true }),
    status: () => ({ panel: "https://vaultwarden.example.com/admin", unlocked: !new URLSearchParams(window.location.search).has("vwlocked") }),
    unlock: () => null,
    users: () => ({
      assignable_roles: ["user", "manager", "admin", "owner"],
      users: [
        { id: "u1", name: "Alex", email: "you@example.com", state: "enabled", two_factor: true, email_verified: true, created_at: "2025-02-11 10:12", last_active: "2026-09-25 09:40",
          memberships: [{ org_id: "o1", org_name: "Acme", role: "owner", status: "confirmed" }, { org_id: "o2", org_name: "Globex", role: "admin", status: "confirmed" }],
          actions: [{ action: "deauth", danger: false, confirm: true }, { action: "disable", danger: false, confirm: true }, { action: "remove_two_factor", danger: true, confirm: true }, { action: "delete", danger: true, confirm: true }] },
        { id: "u2", name: null, email: "anna@example.com", state: "invited", two_factor: false, email_verified: false, created_at: "2026-09-20 18:03", last_active: null,
          memberships: [{ org_id: "o1", org_name: "Acme", role: "user", status: "invited" }],
          actions: [{ action: "resend_invite", danger: false, confirm: false }, { action: "delete", danger: true, confirm: true }] },
        { id: "u3", name: "Old laptop", email: "ops@example.com", state: "disabled", two_factor: false, email_verified: true, created_at: "2024-06-01 12:00", last_active: "2025-01-14 08:22",
          memberships: [],
          actions: [{ action: "enable", danger: false, confirm: false }, { action: "delete", danger: true, confirm: true }] },
      ],
    }),
    orgs: () => [
      { id: "o1", name: "Acme", owners: 1, members: [
        { user_id: "u1", email: "you@example.com", name: "Alex", role: "owner", status: "confirmed" },
        { user_id: "u2", email: "anna@example.com", name: null, role: "user", status: "invited" },
      ] },
      { id: "o2", name: "Globex", owners: 0, members: [{ user_id: "u1", email: "you@example.com", name: "Alex", role: "admin", status: "confirmed" }] },
    ],
    settings: () => [
      { id: "settings", title: "General settings", settings: [
        { name: "domain", label: "Domain URL", description: "This needs to be set to the URL used to access the server, including 'http[s]://' and port, if it's different than the default.", kind: "text", value: "https://vaultwarden.example.com", default: null, editable: true, overridden: true },
        { name: "signups_allowed", label: "Allow new signups", description: "Controls whether new users can register.", kind: "checkbox", value: false, default: "true", editable: true, overridden: true },
        { name: "org_creation_users", label: "Org creation users", description: "Allow org creation only by this list of comma-separated user emails. Blank or 'all' means all users can create orgs; 'none' means no users can create orgs.", kind: "text", value: "you@example.com", default: null, editable: true, overridden: true, choice: { kind: "users", options: ["you@example.com", "anna@example.com", "ops@example.com"], all: "all", none: "none", separator: "," } },
        { name: "invitation_expiration_hours", label: "Invitation token expiration time (in hours)", description: "The number of hours after which an organization invite token, emergency access invite token, email verification token and deletion request token will expire.", kind: "number", value: 120, default: "120", editable: true, overridden: false },
      ] },
      { id: "smtp", title: "SMTP Email Settings", settings: [
        { name: "smtp_host", label: "Host", description: "", kind: "text", value: "smtp.example.com", default: null, editable: true, overridden: true },
        { name: "smtp_port", label: "Port", description: "", kind: "number", value: 587, default: "587", editable: true, overridden: false },
        { name: "smtp_username", label: "Username", description: "", kind: "text", value: "vault@example.com", default: null, editable: true, overridden: true },
        { name: "smtp_password", label: "Password", description: "", kind: "password", value: "demo-smtp-password", default: null, editable: true, overridden: true },
        { name: "smtp_accept_invalid_certs", label: "Accept Invalid Certs (Know the risks!)", description: "DANGEROUS: Allow invalid certificates.", kind: "checkbox", value: false, default: "false", editable: true, overridden: false },
      ] },
      { id: "yubico", title: "Yubikey settings", settings: [
        { name: "yubico_client_id", label: "Client ID", description: "", kind: "text", value: null, default: null, editable: true, overridden: false },
        { name: "yubico_secret_key", label: "Secret Key", description: "", kind: "password", value: null, default: null, editable: true, overridden: false },
      ] },
      { id: "readonly", title: "Read-Only Config", settings: [
        { name: "database_url", label: "Database URL", description: "", kind: "password", value: "data/db.sqlite3", default: null, editable: false, overridden: false },
        { name: "web_vault_enabled", label: "Enable web vault", description: "", kind: "checkbox", value: true, default: "true", editable: false, overridden: false },
      ] },
    ],
    save_settings: () => null,
    reset_settings: () => null,
    backup_db: () => "Backup to 'data/db_20260925.sqlite3' was successful",
    test_smtp: () => null,
    user_action: () => null,
    set_org_role: () => null,
    invite: () => null,
    delete_org: () => null,
    forget: () => null,
  },
  hashicorp: {
    settings: () => HASHICORP_SETTINGS,
    set_settings: (p) => Object.assign(HASHICORP_SETTINGS, p),
    connections: () => LINKS,
    status: () => LINKS[0],
    connect: () => LINKS[0],
    select: () => LINKS[0],
    forget: () => null,
    health: () => HEALTH,
    seal_status: () => SEAL,
    unseal: () => SEAL,
    probe: () => SEAL,
    generate_root: () => ({ done: true }),
    root_tokens: () => ROOTS,
    revoke_root: () => [],
    issue: ({ request }) => {
      const r = request as Record<string, unknown>;
      return {
        issued: { ...r, accessor: "hvs.CAESfresh", created_at: Math.floor(Date.now() / 1000), state: { state: "active" } },
        wrapping_token: r.wrap ? "hvs.wrapped000" : null,
        token: r.wrap ? null : "hvs.plain000",
      };
    },
    issues: () => ISSUED,
    revoke: () => ISSUED,
    policies: () => POLICIES,
    policy: () => POLICY,
    mounts: () => MOUNTS,
    auth_mounts: () => AUTH_MOUNTS,
    secret_list: ({ path }) => {
      const p = String(path ?? "");
      if (p === "") return ["dev/", "ops/", "platform/", "prod/"];
      if (p === "prod/") return ["api-gateway", "billing", "billing-registry", "ci-runner", "metrics", "postgres-replica", "search"];
      return [];
    },
    // As the plugin answers: keys and lengths only; a value one at a time.
    secret_read: ({ mount, path, version }) => {
      const data: Record<string, string> = version ? { ADMIN_PANEL_ENABLED: "false", DATABASE_URI: SECRET_FIELDS.DATABASE_URI } : SECRET_FIELDS;
      return {
        mount,
        path,
        fields: Object.entries(data).map(([key, v]) => ({ key, length: v.length })),
        version: (version as number | undefined) ?? 4,
        updated: version ? "2026-03-01T08:00:00Z" : "2026-05-19T13:30:35.757554003Z",
      };
    },
    secret_read_full: ({ mount, path, version }) => ({ mount, path, data: SECRET_FIELDS, version: (version as number | undefined) ?? 4, updated: null }),
    secret_value: ({ key }) => (SECRET_FIELDS as Record<string, string>)[key as string] ?? "",
    secret_copy: () => 30,
    secret_rollback: ({ mount, path }) => ({ mount, path, fields: [], version: 5, updated: new Date().toISOString() }),
    secret_write: ({ mount, path, data }) => ({
      mount,
      path,
      fields: Object.entries(data as Record<string, string>).map(([key, v]) => ({ key, length: v.length })),
      version: 5,
      updated: new Date().toISOString(),
    }),
    secret_meta: ({ mount, path }) => ({
      mount,
      path,
      current_version: 4,
      oldest_version: 1,
      max_versions: 0,
      cas_required: false,
      delete_version_after: "0s",
      custom_metadata: { owner: "platform", ticket: "OPS-1187" },
      created: "2026-02-11T09:12:00Z",
      updated: "2026-05-19T13:30:35Z",
      versions: [
        { version: 4, created: "2026-05-19T13:30:35Z", deleted: null, destroyed: false },
        { version: 3, created: "2026-04-02T10:00:00Z", deleted: "2026-04-03T10:00:00Z", destroyed: false },
        { version: 2, created: "2026-03-01T08:00:00Z", deleted: null, destroyed: false },
        { version: 1, created: "2026-02-11T09:12:00Z", deleted: null, destroyed: true },
      ],
    }),
    secret_meta_write: (a) => secretMeta(a),
    secret_undelete: (a) => secretMeta(a),
    secret_destroy: (a) => secretMeta(a),
    kv_config: () => ({ max_versions: 0, cas_required: false, delete_version_after: "0s" }),
    kv_config_write: ({ config }) => config,
    mount_enable: ({ form }) => {
      const f = form as { path: string; kind: string; description: string; auth: boolean; kv_version: number | null };
      const base = (f.auth ? (AUTH_MOUNTS as unknown[]) : (MOUNTS as unknown[])) as Record<string, unknown>[];
      return [...base, { path: f.auth ? `auth/${f.path}` : f.path, kind: f.kind, description: f.description, kv2: f.kv_version === 2, accessor: "new_1", default_lease_ttl: 0, max_lease_ttl: 0, auth: f.auth }];
    },
    mount_disable: ({ path, auth }) => ((auth ? AUTH_MOUNTS : MOUNTS) as { path: string }[]).filter((m) => m.path !== path),
    mount_tune: ({ auth }) => (auth ? AUTH_MOUNTS : MOUNTS),
    secret_delete: () => ["api-gateway", "billing", "billing-registry", "ci-runner", "postgres-replica", "search"],
    ensure_policy_admin: () => ["default", "keyward-policy-admin", "kv-read", "pki-issue", "root"],
    put_policy: () => ["default", "kv-read", "pki-issue", "root"],
    delete_policy: () => ["default", "pki-issue", "root"],
  },
  ssh: {
    keys: () => SSH_KEYS,
    // A pasted key is "read" by its first line: an OpenSSH header reads, one
    // with "LOCKED" in it asks for a passphrase until one is given, anything
    // else is not a key.
    generate_key: () => ({
      private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nstand\n-----END OPENSSH PRIVATE KEY-----",
      public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKTG3dVKzboR6QHEOzShz/hCRc7otdoD/K3WE84 new@keyward",
      fingerprint: "SHA256:tR70x1hZkzQ5uhFUie9wTgz8qHeuEh3LeN7j+8lizi4",
      algorithm: "ssh-ed25519",
    }),
    inspect_key: ({ private_key, passphrase }) => {
      const text = String(private_key ?? "");
      if (text.startsWith("ssh-")) throw "err.sshKeyIsPublic";
      if (!text.includes("BEGIN OPENSSH PRIVATE KEY")) throw "err.sshKeyUnsupported";
      if (text.includes("LOCKED") && !passphrase) throw "err.sshKeyNeedsPassphrase";
      return {
        public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIACnh8bnnktS8RgGbWJqbI4+BOKen7uiuFML8UogMdp+ you@laptop",
        fingerprint: "SHA256:/isoPc4zsyI5eGGgBTllIrgXx/hHi7HWN3AqKBECz5w",
        algorithm: "ssh-ed25519",
      };
    },
    set_hosts: ({ entry_id, hosts, user, port }) => {
      const key = SSH_KEYS.find((k) => k.id === entry_id);
      if (key) {
        key.hosts = String(hosts ?? "");
        if (user !== undefined) key.user = String(user);
        if (port !== undefined) key.port = String(port);
      }
      return SSH_KEYS;
    },
    hosts: () => [],
    resolve: () => null,
    status: () => ({
      mappings: 6,
      live_sockets: 2,
      warnings: [],
      unmapped: SSH_KEYS.filter((k) => !k.hosts).map((k) => k.name),
      socket: SSH_SETTINGS.shared_socket ? "~/.keyward/agent.sock" : null,
    }),
    settings: () => SSH_SETTINGS,
    set_settings: (p) => Object.assign(SSH_SETTINGS, p),
    snippet: () => SSH_SNIPPET,
    // The terminal speaks its sealed protocol for real, over a make-believe
    // shell.
    ...STAND_TERMINAL,
  },
};

// `?locked=1` — the stand in its locked state, to look at the unlock screen;
// `?pin=1` — with a PIN set, `?nobio=1` — without Touch ID.
{
  const q = new URLSearchParams(location.search);
  const st = CANNED.daemon_status as { vault: { state: string }; pin: boolean; biometric: boolean };
  if (q.has("locked")) {
    st.vault = { state: "locked", email: "you@example.com", server: "https://vaultwarden.example.com", entries: 0, tagged: 0 } as unknown as typeof st.vault;
    const acc = CANNED.vault_accounts as { accounts: { state: unknown }[] };
    acc.accounts[0].state = st.vault;
  }
  if (q.has("pin")) st.pin = true;
  if (q.has("nobio")) st.biometric = false;
  // `?sshkey=1` — the card (and, with `&edit=1`, the form) of an ssh key.
  if (q.has("sshkey")) {
    CANNED.item_detail = {
      id: "k1",
      name: "id_ed25519 — production",
      kind: "ssh_key",
      folder_name: null,
      passkeys: [],
      uris: [],
      reprompt: false,
      deleted: false,
      favorite: false,
      fields: [
        { key: "fingerprint", label: "fingerprint", value: "SHA256:tR70x1hZkzQ5uhFUie9wTgz8qHeuEh3LeN7j+8lizi4", secret: null, hidden: false, mono: true, extra: [] },
        { key: "publicKey", label: "publicKey", value: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI-demo-key alex@demo.example", secret: null, hidden: false, mono: true, extra: [] },
        { key: "privateKey", label: "privateKey", value: null, secret: "private_key", hidden: true, mono: true, extra: [] },
      ],
      custom: [
        { name: "kw-host", value: "git.prod.demo.example, *.prod.demo.example", hidden: false, kind: 0, linked_id: null },
        { name: "kw-confirm", value: "yes", hidden: false, kind: 0, linked_id: null },
      ],
    };
  }
  // Rich detail variants for product screenshots. They keep every secret
  // synthetic while exercising the same components as live vault data.
  if (q.get("fixture") === "card") {
    CANNED.item_detail = {
      id: "i6", name: "Stripe — finance", kind: "card", folder_name: "Personal", passkeys: [],
      uris: ["https://dashboard.stripe.com"], reprompt: true, deleted: false, favorite: false,
      fields: [
        { key: "cardholder", label: "cardholder", value: "ALEX MORGAN", secret: null, hidden: false, mono: false, extra: [] },
        // "Other" intentionally makes the UI detect Visa from the visible IIN.
        { key: "brand", label: "brand", value: "Other", secret: null, hidden: false, mono: false, extra: [] },
        { key: "expiry", label: "expiry", value: "09/2029", secret: null, hidden: false, mono: true, extra: [] },
        { key: "cardNumber", label: "cardNumber", value: "424242 ···· 4242", secret: "card_number", hidden: true, mono: true, extra: [] },
        { key: "cardCode", label: "cardCode", value: null, secret: "card_code", hidden: true, mono: true, extra: [] },
      ],
      custom: [{ name: "billing team", value: "Platform Finance", hidden: false, kind: 0, linked_id: null }],
    };
  }
  if (q.get("fixture") === "identity") {
    CANNED.item_detail = {
      id: "i7", name: "Alex Morgan", kind: "identity", folder_name: "Personal", passkeys: [], uris: [], reprompt: false, deleted: false, favorite: false,
      fields: [
        { key: "fullName", label: "fullName", value: "Alex Morgan", secret: null, hidden: false, mono: false, extra: [] },
        { key: "email", label: "email", value: "alex@demo.example", secret: "username", hidden: false, mono: false, extra: [] },
        { key: "phone", label: "phone", value: "+1 202 555 0148", secret: "username", hidden: false, mono: true, extra: [] },
        { key: "address1", label: "address1", value: "42 Demo Street", secret: null, hidden: false, mono: false, extra: [] },
        { key: "passportNumber", label: "passportNumber", value: null, secret: "notes", hidden: true, mono: true, extra: [] },
      ],
      custom: [{ name: "preferred locale", value: "en-GB", hidden: false, kind: 0, linked_id: null }],
    };
  }
}

// The stand speaks the window's sealed protocol for real: the page opens a
// session, and every value a secret-bearing command returns is sealed, exactly
// as the Rust half does it. The page's code has no plain path to fall back on.
const SEALED_COMMANDS = new Set(["reveal_secret", "reveal_generated", "generate_password", "two_factor_recovery_code"]);
let standKey: Promise<CryptoKey> | null = null;

async function standOpen(pagePublic: string): Promise<string> {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const mine = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const page = unb64(pagePublic);
  const theirs = await crypto.subtle.importKey("raw", page, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const secret = await crypto.subtle.deriveBits({ name: "ECDH", public: theirs }, pair.privateKey, 256);
  standKey = windowKey(secret, page, mine, "encrypt");
  return b64(mine);
}

async function standSeal(value: unknown): Promise<unknown> {
  if (value === null || value === undefined) return value;
  if (!standKey) throw "err.channelRequired";
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await standKey, new TextEncoder().encode(String(value))));
  const out = new Uint8Array(iv.length + sealed.length);
  out.set(iv, 0);
  out.set(sealed, iv.length);
  return { sealed: b64(out) };
}

// This is how `@tauri-apps/api` finds the bridge into the window; it is
// replaced whole.
(window as unknown as { __TAURI_INTERNALS__: unknown }).__TAURI_INTERNALS__ = {
  invoke: async (cmd: string, args?: Record<string, unknown>) => {
    // One envelope for every plugin: it is taken apart as the daemon takes it
    // apart.
    // `?down` — the daemon does not answer: the screen that says so.
    if (cmd === "daemon_status" && new URLSearchParams(window.location.search).has("down")) throw "the daemon is not answering";
    if (cmd === "site_icon") return demoFavicon(String(args?.domain ?? ""));
    if (cmd === "item_detail") {
      const q = new URLSearchParams(window.location.search);
      // A named fixture deliberately pins a special state for screenshots;
      // every normal click still follows its entry id.
      if (q.has("sshkey") || q.has("fixture")) return CANNED.item_detail;
      return previewItemDetail(String(args?.entryId ?? ""));
    }
    if (cmd === "plugin_call") {
      const { plugin, action, payload } = (args ?? {}) as {
        plugin: string;
        action: string;
        payload?: Record<string, unknown> | null;
      };
      const run = PLUGIN_OPS[plugin]?.[action];
      if (!run) throw `the stand does not know the operation ${plugin}.${action}`;
      return run(payload ?? {});
    }
    if (cmd === "window_seal_open") return standOpen(String(args?.public ?? ""));
    const dyn = DYNAMIC[cmd];
    const result = dyn ? await dyn(args ?? {}) : (CANNED[cmd] ?? null);
    return SEALED_COMMANDS.has(cmd) ? standSeal(result) : result;
  },
  transformCallback: (cb: unknown) => cb,
  metadata: {},
};

const { default: App } = await import("./App");

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
