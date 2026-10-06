import { useEffect, useMemo, useState, type ReactNode } from "react";
import { BrowserExtensions } from "./Extensions";
import { invoke } from "@tauri-apps/api/core";

/// What the daemon knows about the sensor just now.
type BiometricState = { available: boolean; problem: string | null; last_failure: string | null };
import QRCode from "qrcode";
import { Alert, CopyButton, DangerZone, Field, Icon, Modal, Picker, Row, Rows, ScreenHead, Section, Segmented, Toggle, inkOn } from "../ui";
import { locale, setLanguage, t, tMaybe } from "../i18n";
import type { Key } from "../i18n";
import type {
  AccountList,
  AccountProfile,
  AppSettings,
  AuthenticatorSetup,
  Device,
  EmailTwoFactorSetup,
  ExportFormat,
  KdfInfo,
  LockTimeout,
  LoginReply,
  Status,
  TwoFactorProvider,
  TwoFactorStatus,
} from "../types";
import { usePlugins } from "../plugins/call";
import { previewPalette, watchScheme } from "../accent";
import { pluginEntry } from "../plugins";
import { PluginsSettings } from "../plugins/Plugins";
import { PasswordInput } from "../PasswordInput";
import { TwoFactorForm } from "../TwoFactor";
import { invokeSecret } from "../seal";

/// A settings page: our own, or a plugin's — then this is its identifier.
type Tab = string;

/// The settings in Bitwarden's sections: the account, safety, the application,
/// plus our own — ssh and "about". The order and the set of sections repeat
/// Bitwarden's desktop, so that somebody coming from there does not have to
/// look for the familiar afresh.
/// Each settings page's icon: the column's entry and the page's head share it.
export const SETTINGS_ICON: Record<string, string> = {
  account: "identity",
  security: "shield",
  preferences: "eye",
  app: "settings",
  plugins: "puzzle",
  about: "note",
};

export function SettingsScreen({
  status,
  accounts,
  onChanged,
  onAddAccount,
  onSettingsChanged,
  onCopied,
  hold,
  tab,
}: {
  status: Status;
  accounts: AccountList | null;
  onChanged: () => void;
  onAddAccount: () => void;
  /// The settings have been saved — the shell has to know about the theme and
  /// the icons at once.
  onSettingsChanged?: (s: AppSettings) => void;
  onCopied?: (text: string) => void;
  /// Hold back the polling of the daemon while a password is being changed or a
  /// second factor set up: otherwise the shell sees "logged out" and replaces
  /// the settings with the gate halfway through.
  hold?: (on: boolean) => void;
  tab: Tab;
}) {
  const plugins = usePlugins();
  // One page, one subject. Safety, the application, the plugins, their
  // settings and the help used to lie in one scroll: reaching the bottom meant
  // leafing past everything else, and coming back meant hunting with the
  // eyes.
  const plugin = plugins.find((m) => m.id === tab && m.enabled);
  const PluginBlock = plugin ? pluginEntry(plugin).SettingsSection : null;
  // The same head as every other screen: the page's name and icon, as the
  // column names it.
  const title = plugin ? tMaybe(plugin.title, plugin.title) : t(`settings.tab.${tab}` as Key);
  return (
    <div className="settings">
      <ScreenHead icon={plugin ? plugin.icon : SETTINGS_ICON[tab]} title={title} />
      {tab === "account" && (
        <AccountTab
          status={status}
          accounts={accounts}
          onChanged={onChanged}
          onAddAccount={onAddAccount}
          onCopied={onCopied ?? (() => {})}
          hold={hold ?? (() => {})}
        />
      )}
      {tab === "security" && (
        <SecurityTab status={status} onChanged={onChanged} onSettingsChanged={onSettingsChanged} />
      )}
      {tab === "preferences" && <AppTab part="preferences" onSettingsChanged={onSettingsChanged} />}
      {tab === "app" && <AppTab part="app" onSettingsChanged={onSettingsChanged} />}
      {tab === "plugins" && <PluginsSettings />}
      {tab === "about" && <AboutTab status={status} />}
      {/* A plugin's page: its own block and nothing more. */}
      {PluginBlock && <PluginBlock />}
    </div>
  );
}

/// The "the profile has changed" event — for the avatar on the rail.
export const PROFILE_EVENT = "kw:profile";

// ── The common pieces ────────────────────────────────────────────────────

function useAction(onChanged?: () => void) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      onChanged?.();
      return true;
    } catch (e) {
      setError(String(e));
      return false;
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, run, clear: () => setError(null) };
}

function Chip({ on, children }: { on: boolean; children: ReactNode }) {
  return (
    <span className={`chip ${on ? "ok" : ""}`}>
      <span className="dot" aria-hidden="true" />
      {children}
    </span>
  );
}

function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return new Intl.DateTimeFormat(locale(), { dateStyle: "medium" }).format(d);
}

function fmtWhen(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return new Intl.DateTimeFormat(locale(), { dateStyle: "medium", timeStyle: "short" }).format(d);
}

function kdfLabel(kdf: KdfInfo): string {
  const n = new Intl.NumberFormat(locale());
  return kdf.kind === "pbkdf2"
    ? t("settings.kdf.pbkdf2Label", { n: n.format(kdf.iterations) })
    : t("settings.kdf.argon2Label", { n: kdf.iterations, m: kdf.memory_mib, p: kdf.parallelism });
}

/// The second-factor step after an operation that counts as a login. It holds
/// the providers until the step is passed, and tells the dialogue what to draw
/// in place of its own body.
function useLoginFlow(onFinished: () => void) {
  const [providers, setProviders] = useState<TwoFactorProvider[] | null>(null);
  const handle = (reply: LoginReply) => {
    if (reply.kind === "two_factor") setProviders(reply.providers);
    else onFinished();
  };
  const step = providers ? (
    <TwoFactorForm
      providers={providers}
      onDone={() => {
        setProviders(null);
        onFinished();
      }}
    />
  ) : null;
  return { handle, step };
}

/// Holds back the shell's polling while the dialogue is open.
function useHold(hold: (on: boolean) => void) {
  useEffect(() => {
    hold(true);
    return () => hold(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
}

// ── The account ──────────────────────────────────────────────────────────

/// Bitwarden's avatar palette — the same eight the web client offers, so that
/// the colour matches in every client of one account.
const AVATAR_COLORS = ["#175DDC", "#33ffcc", "#ff33cc", "#ffcc33", "#33ccff", "#ff6633", "#7f33ff", "#33ff66"];

// Appearance is deliberately independent from an account avatar. These tones
// recolour the entire UI ladder (active states, focus and glass), not data
// semantics such as danger or a payment network.
/// The palettes on offer: one colour each, from which the whole theme is
/// derived. `null` is keyward's own.
const PALETTES: { id: string; color: string | null }[] = [
  { id: "default", color: null },
  { id: "ocean", color: "#175DDC" },
  { id: "teal", color: "#0E9F8A" },
  { id: "forest", color: "#2F9E55" },
  { id: "sand", color: "#C8942A" },
  { id: "ember", color: "#D36B3C" },
  { id: "rose", color: "#D15A91" },
  { id: "lilac", color: "#A879E6" },
  { id: "graphite", color: "#6B7280" },
];

/// The palettes as small windows of their own: a ground, a card on it, a line
/// of text and the accent — what the whole theme will look like, not a dot of
/// one colour. And a colour of one's own through the system's picker.
function PalettePicker({
  value,
  theme,
  onChange,
}: {
  value: string | null;
  theme: AppSettings["theme"];
  onChange: (color: string | null) => void;
}) {
  // The previews are drawn for the scheme that is on: the system's may change
  // under the window.
  const [scheme, setScheme] = useState(0);
  useEffect(() => watchScheme(() => setScheme((n) => n + 1)), []);
  const current = value?.toLowerCase() ?? null;
  const custom = current !== null && PALETTES.every((p) => p.color?.toLowerCase() !== current);
  const shown = useMemo(
    () => [...PALETTES, ...(custom ? [{ id: "custom", color: value }] : [])].map((p) => ({ ...p, tokens: previewPalette(p.color) })),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [theme, scheme, custom ? value : null],
  );
  return (
    <div className="palettes" role="radiogroup" aria-label={t("settings.accent")}>
      {shown.map((p) => {
        const on = (p.color?.toLowerCase() ?? null) === current;
        const tk = p.tokens ?? {};
        const name = p.id === "custom" ? t("settings.palette.custom") : t(`settings.palette.${p.id}` as Key);
        return (
          <button
            key={p.id}
            type="button"
            role="radio"
            aria-checked={on}
            className={`palette ${on ? "on" : ""}`}
            title={name}
            onClick={() => onChange(p.color)}
          >
            <span className="palette-win" style={{ background: tk["--ink"], borderColor: tk["--edge"] }}>
              <span className="palette-rail" style={{ background: tk["--rail"] }} />
              <span className="palette-card" style={{ background: tk["--surface"], borderColor: tk["--edge-soft"] }}>
                <span className="palette-line" style={{ background: tk["--dim"] }} />
                <span className="palette-line short" style={{ background: tk["--faint"] }} />
                <span className="palette-btn" style={{ background: tk["--blue"] }} />
              </span>
            </span>
            <span className="palette-name">{name}</span>
          </button>
        );
      })}
      <label className="palette add" title={t("settings.palette.pick")}>
        <span className="palette-win">
          <Icon name="plus" size={14} />
        </span>
        <span className="palette-name">{t("settings.palette.pick")}</span>
        <input type="color" value={value ?? "#7865f5"} aria-label={t("settings.palette.pick")} onChange={(e) => onChange(e.target.value)} />
      </label>
    </div>
  );
}

function initials(profile: AccountProfile): string {
  const source = profile.name?.trim() || profile.email;
  const words = source.split(/[\s@._-]+/).filter(Boolean);
  return (words.length >= 2 ? words[0][0] + words[1][0] : source.slice(0, 2)).toUpperCase();
}


type AccountModal =
  | { kind: "password" }
  | { kind: "email" }
  | { kind: "twofactor" }
  | { kind: "kdf" }
  | { kind: "devices" }
  | { kind: "export" }
  | { kind: "confirm"; what: "deauthorize" | "purge" | "delete" };

function AccountTab({
  status,
  accounts,
  onChanged,
  onAddAccount,
  onCopied,
  hold,
}: {
  status: Status;
  accounts: AccountList | null;
  onChanged: () => void;
  onAddAccount: () => void;
  onCopied: (text: string) => void;
  hold: (on: boolean) => void;
}) {
  const [profile, setProfile] = useState<AccountProfile | null>(null);
  const [profileError, setProfileError] = useState<string | null>(null);
  const [modal, setModal] = useState<AccountModal | null>(null);
  const { busy, error, run } = useAction(onChanged);
  const active = accounts?.accounts.find((a) => a.account.id === accounts.active);
  const others = accounts?.accounts.filter((a) => a.account.id !== accounts.active) ?? [];

  const loadProfile = () => {
    invoke<AccountProfile>("account_profile")
      .then((p) => {
        setProfile(p);
        setProfileError(null);
      })
      .catch((e) => setProfileError(String(e)));
  };
  // The profile is re-read together with the vault's state: switching accounts
  // or logging in again changes it too.
  useEffect(loadProfile, [status.vault, accounts?.active]);

  const changed = () => {
    loadProfile();
    onChanged();
    // The shell draws the avatar on the rail in the same colour — it has to be
    // told.
    window.dispatchEvent(new CustomEvent(PROFILE_EVENT));
  };

  return (
    <>
      <Section title={t("settings.profile")}>
        {profile ? (
          <Profile profile={profile} onChanged={changed} onCopied={onCopied} />
        ) : profileError ? (
          <Alert message={profileError} onRetry={loadProfile} />
        ) : (
          <p className="hint">{t("settings.profile.loading")}</p>
        )}
      </Section>

      <Section title={t("settings.access")} tone="mint">
        <Rows>
          <Row title={t("settings.password")} hint={t("settings.passwordHint")}>
            <button type="button" className="btn" onClick={() => setModal({ kind: "password" })}>
              {t("action.change")}
            </button>
          </Row>
          <Row title={t("settings.email")} hint={profile?.email ?? active?.account.email ?? "—"}>
            <button type="button" className="btn" onClick={() => setModal({ kind: "email" })}>
              {t("action.change")}
            </button>
          </Row>
          <Row
            title={t("settings.twofactor")}
            hint={
              profile ? (
                <Chip on={profile.two_factor_enabled}>{profile.two_factor_enabled ? t("settings.twofactor.on") : t("settings.twofactor.off")}</Chip>
              ) : (
                t("settings.twofactorHint")
              )
            }
          >
            <button type="button" className="btn" onClick={() => setModal({ kind: "twofactor" })}>
              {t("action.configure")}
            </button>
          </Row>
          <Row title={t("settings.kdf")} hint={profile ? kdfLabel(profile.kdf) : t("settings.kdfHint")}>
            <button type="button" className="btn" disabled={!profile} onClick={() => setModal({ kind: "kdf" })}>
              {t("action.change")}
            </button>
          </Row>
          <Row title={t("settings.devices")} hint={t("settings.devicesHint")}>
            <button type="button" className="btn" onClick={() => setModal({ kind: "devices" })}>
              {t("action.show")}
            </button>
          </Row>
          <Row title={t("settings.export")} hint={t("settings.exportHint")}>
            <button type="button" className="btn" onClick={() => setModal({ kind: "export" })}>
              {t("settings.export.action")}
            </button>
          </Row>
        </Rows>
      </Section>

      <Section title={t("accounts.title")} tone="amber">
        <Rows>
          <Row title={active?.account.email ?? "—"} hint={active?.account.base_url.replace(/^https?:\/\//, "") ?? ""}>
            <div className="row-actions">
              <button type="button" className="btn" onClick={onAddAccount}>
                {t("settings.account.change")}
              </button>
              {accounts?.active && (
                <button type="button" className="btn" disabled={busy} onClick={() => void run(() => invoke("vault_logout", { id: accounts.active! }))}>
                  {t("accounts.logout")}
                </button>
              )}
            </div>
          </Row>
          {others.map((a) => (
            <Row key={a.account.id} title={a.account.email} hint={a.account.base_url.replace(/^https?:\/\//, "")}>
              <div className="row-actions">
                <button type="button" className="btn" disabled={busy} onClick={() => void run(() => invoke("vault_switch_account", { id: a.account.id }))}>
                  {t("accounts.switch")}
                </button>
                <button type="button" className="btn" disabled={busy} onClick={() => void run(() => invoke("vault_logout", { id: a.account.id }))}>
                  {t("accounts.logout")}
                </button>
              </div>
            </Row>
          ))}
        </Rows>
        <button type="button" className="btn add-account" onClick={onAddAccount}>
          <Icon name="plus" size={13} />
          {t("accounts.add")}
        </button>
        {error && <Alert message={error} />}
      </Section>

      <DangerZone
        title={t("settings.danger")}
        items={[
          {
            label: t("settings.deauthorize"),
            hint: t("settings.deauthorizeHint"),
            action: t("settings.deauthorize.action"),
            tone: "warn",
            onClick: () => setModal({ kind: "confirm", what: "deauthorize" }),
          },
          {
            label: t("settings.purge"),
            hint: t("settings.purgeHint"),
            action: t("settings.purge.action"),
            onClick: () => setModal({ kind: "confirm", what: "purge" }),
          },
          {
            label: t("settings.deleteAccount"),
            hint: t("settings.deleteAccountHint"),
            action: t("settings.deleteAccount.action"),
            onClick: () => setModal({ kind: "confirm", what: "delete" }),
          },
        ]}
      />

      {modal?.kind === "password" && <ChangePasswordModal hint={profile?.master_password_hint ?? ""} onClose={() => setModal(null)} onChanged={changed} hold={hold} />}
      {modal?.kind === "email" && <ChangeEmailModal email={profile?.email ?? ""} onClose={() => setModal(null)} onChanged={changed} hold={hold} />}
      {modal?.kind === "twofactor" && <TwoFactorModal onClose={() => setModal(null)} onChanged={changed} onCopied={onCopied} />}
      {modal?.kind === "kdf" && profile && <KdfModal kdf={profile.kdf} onClose={() => setModal(null)} onChanged={changed} hold={hold} />}
      {modal?.kind === "devices" && <DevicesModal onClose={() => setModal(null)} onDeauthorize={() => setModal({ kind: "confirm", what: "deauthorize" })} />}
      {modal?.kind === "export" && <ExportModal onClose={() => setModal(null)} onCopied={onCopied} />}
      {modal?.kind === "confirm" && <ConfirmModal what={modal.what} onClose={() => setModal(null)} onChanged={changed} hold={hold} />}
    </>
  );
}

/// The profile's header: the avatar with its palette, the name edited in
/// place, the email, the date, the fingerprint. The name is saved on Enter and
/// on losing focus — a "Save" button of its own for one field would be noise.
function Profile({ profile, onChanged, onCopied }: { profile: AccountProfile; onChanged: () => void; onCopied: (text: string) => void }) {
  const [name, setName] = useState(profile.name ?? "");
  const { busy, error, run } = useAction(onChanged);
  useEffect(() => setName(profile.name ?? ""), [profile.name]);

  const color = profile.avatar_color ?? AVATAR_COLORS[0];
  const saveName = () => {
    const next = name.trim();
    if (next === (profile.name ?? "")) return;
    void run(() => invoke("account_set_profile", { name: next, hint: profile.master_password_hint }));
  };
  const pick = (c: string | null) => void run(() => invoke("account_set_avatar", { color: c }));

  return (
    <>
      <div className="profile">
        <span className="avatar-big" style={{ background: color, color: inkOn(color) }} aria-hidden="true">
          {initials(profile)}
        </span>
        <div className="profile-main">
          <span className="field-caption">{t("settings.profile.name")}</span>
          <input
            className="inline-name"
            value={name}
            placeholder={t("settings.profile.name")}
            aria-label={t("settings.profile.name")}
            onChange={(e) => setName(e.target.value)}
            onBlur={saveName}
            onKeyDown={(e) => {
              if (e.key === "Enter") (e.target as HTMLInputElement).blur();
            }}
            disabled={busy}
            spellCheck={false}
          />
          <span className="hint mono">{profile.email}</span>
          <span className="hint">
            {t("settings.profile.since", { date: fmtDate(profile.creation_date) })}
            {profile.premium ? ` · ${t("settings.profile.premium")}` : ""}
          </span>
        </div>
      </div>

      <div className="swatches" role="radiogroup" aria-label={t("settings.avatar")}>
        {AVATAR_COLORS.map((c) => (
          <button
            key={c}
            type="button"
            role="radio"
            aria-checked={color.toLowerCase() === c.toLowerCase()}
            className={`swatch ${color.toLowerCase() === c.toLowerCase() ? "on" : ""}`}
            style={{ background: c }}
            title={c}
            disabled={busy}
            onClick={() => pick(c)}
          />
        ))}
        {/* A colour of one's own through the system's palette rather than a
            field with a hex code and an "Apply" button: two controls too many
            for one action. */}
        <label className={`swatch custom ${AVATAR_COLORS.every((c) => c.toLowerCase() !== color.toLowerCase()) ? "on" : ""}`} title={t("settings.avatar.custom")} style={{ background: color }}>
          <Icon name="plus" size={12} />
          <input type="color" value={color} aria-label={t("settings.avatar.custom")} disabled={busy} onChange={(e) => pick(e.target.value)} />
        </label>
      </div>
      {/* The avatar's colour is the account's, and it is easily taken for the
          application's: the way to that one is said right here. */}
      <span className="hint">{t("settings.avatarNotPalette")}</span>

      <Rows>
        <Row title={t("settings.fingerprint")} hint={t("settings.fingerprintHint")}>
          <span className="fingerprint">
            <span className="mono">{profile.fingerprint.join("-")}</span>
            <CopyButton value={profile.fingerprint.join("-")} onCopied={onCopied} title={t("action.copy")} />
          </span>
        </Row>
      </Rows>
      {error && <Alert message={error} />}
    </>
  );
}

/// An estimate of a password's strength — rough but honest: the length by the
/// size of the alphabet. That is enough to tell "qwerty123" from a generated
/// one.
function strength(pw: string): { bits: number; level: 0 | 1 | 2 | 3 | 4 } {
  if (!pw) return { bits: 0, level: 0 };
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
  const bits = pw.length * Math.log2(pool || 1);
  const level = bits < 36 ? 1 : bits < 60 ? 2 : bits < 90 ? 3 : 4;
  return { bits, level };
}

function Strength({ value }: { value: string }) {
  const { level } = strength(value);
  const labels: Key[] = ["strength.none", "strength.weak", "strength.fair", "strength.good", "strength.strong"];
  return (
    <div className={`strength l${level}`} aria-live="polite">
      <span className="bar">
        {[1, 2, 3, 4].map((i) => (
          <i key={i} className={i <= level ? "on" : ""} />
        ))}
      </span>
      <span className="hint">{t(labels[level])}</span>
    </div>
  );
}

function ChangePasswordModal({ hint: initialHint, onClose, onChanged, hold }: { hint: string; onClose: () => void; onChanged: () => void; hold: (on: boolean) => void }) {
  useHold(hold);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [hint, setHint] = useState(initialHint);
  const { busy, error, run } = useAction();
  const flow = useLoginFlow(() => {
    onChanged();
    onClose();
  });

  const mismatch = again !== "" && again !== next;
  const tooShort = next !== "" && next.length < 12;
  // The daemon will refuse a password equal to the current one — there is no
  // point waiting for the network.
  const sameAsCurrent = next !== "" && next === current;
  const ready = current && next && next === again && next.length >= 12 && !sameAsCurrent && !busy;
  const submit = () => {
    if (!ready) return;
    void run(async () => {
      const reply = await invoke<LoginReply>("account_change_password", { current, new: next, hint: hint.trim() || null });
      flow.handle(reply);
    });
  };

  if (flow.step) {
    return (
      <Modal title={t("twofactor.title")} onClose={onClose}>
        <p className="hint">{t("settings.twofactor.afterChange")}</p>
        {flow.step}
      </Modal>
    );
  }

  return (
    <Modal
      title={t("settings.password.title")}
      onClose={onClose}
      onSubmit={submit}
      footer={
        <button type="button" className="btn primary" disabled={!ready} onClick={submit}>
          {busy ? t("action.saving") : t("settings.password.action")}
        </button>
      }
    >
      <p className="hint">{t("settings.password.body")}</p>
      <div className="field">
        <label>{t("settings.password.current")}</label>
        <PasswordInput value={current} onChange={setCurrent} autoFocus ariaLabel={t("settings.password.current")} />
      </div>
      <div className="field">
        <label>{t("settings.password.new")}</label>
        <PasswordInput value={next} onChange={setNext} generate ariaLabel={t("settings.password.new")} />
        <Strength value={next} />
        {tooShort && <span className="hint warn">{t("settings.password.short")}</span>}
        {sameAsCurrent && <span className="hint warn">{t("settings.password.same")}</span>}
      </div>
      <div className="field">
        <label>{t("settings.password.again")}</label>
        <PasswordInput value={again} onChange={setAgain} ariaLabel={t("settings.password.again")} />
        {mismatch && <span className="hint warn">{t("settings.password.mismatch")}</span>}
      </div>
      <div className="field">
        <label>{t("settings.password.hint")}</label>
        <input value={hint} onChange={(e) => setHint(e.target.value)} placeholder={t("settings.password.hintPlaceholder")} aria-label={t("settings.password.hint")} />
      </div>
      {error && <Alert message={error} />}
    </Modal>
  );
}

function ChangeEmailModal({ email, onClose, onChanged, hold }: { email: string; onClose: () => void; onChanged: () => void; hold: (on: boolean) => void }) {
  useHold(hold);
  const [password, setPassword] = useState("");
  const [next, setNext] = useState("");
  const [token, setToken] = useState("");
  const [step, setStep] = useState<"email" | "code">("email");
  const { busy, error, run } = useAction();
  const flow = useLoginFlow(() => {
    onChanged();
    onClose();
  });

  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(next) && next.toLowerCase() !== email.toLowerCase();
  const ready = step === "email" ? Boolean(password) && emailOk && !busy : Boolean(token) && !busy;
  const submit = () => {
    if (!ready) return;
    void run(async () => {
      if (step === "email") {
        await invoke("account_email_token", { masterPassword: password, newEmail: next });
        setStep("code");
      } else {
        const reply = await invoke<LoginReply>("account_change_email", { masterPassword: password, newEmail: next, token });
        flow.handle(reply);
      }
    });
  };

  if (flow.step) {
    return (
      <Modal title={t("twofactor.title")} onClose={onClose}>
        <p className="hint">{t("settings.twofactor.afterChange")}</p>
        {flow.step}
      </Modal>
    );
  }

  return (
    <Modal
      title={t("settings.email.title")}
      onClose={onClose}
      onSubmit={submit}
      footer={
        <button type="button" className="btn primary" disabled={!ready} onClick={submit}>
          {busy ? t("action.saving") : step === "email" ? t("settings.email.sendCode") : t("settings.email.action")}
        </button>
      }
    >
      {step === "email" ? (
        <>
          <p className="hint">{t("settings.email.body")}</p>
          <div className="field">
            <label>{t("settings.email.new")}</label>
            <input value={next} onChange={(e) => setNext(e.target.value)} placeholder={email} aria-label={t("settings.email.new")} autoFocus spellCheck={false} autoCapitalize="off" inputMode="email" />
          </div>
          <div className="field">
            <label>{t("settings.confirm.password")}</label>
            <PasswordInput value={password} onChange={setPassword} ariaLabel={t("settings.confirm.password")} />
          </div>
        </>
      ) : (
        <>
          <p className="hint">{t("settings.email.codeBody", { email: next })}</p>
          <div className="field">
            <label>{t("settings.email.code")}</label>
            <input value={token} onChange={(e) => setToken(e.target.value)} aria-label={t("settings.email.code")} inputMode="numeric" autoFocus spellCheck={false} />
          </div>
          <button type="button" className="link" disabled={busy} onClick={() => void run(() => invoke("account_email_token", { masterPassword: password, newEmail: next }))}>
            {t("twofactor.resendEmail")}
          </button>
        </>
      )}
      {error && <Alert message={error} />}
    </Modal>
  );
}

type TwoFactorView =
  | { kind: "list" }
  | { kind: "auth" }
  | { kind: "email" }
  | { kind: "recovery" }
  | { kind: "disable"; provider: number; name: string };

/// The second factor is a dialogue that is a list: every method a row with its
/// state and a button. Every action begins with the master password: the server
/// asks for it on every request, and asking once "for everything" would be a
/// lie.
function TwoFactorModal({ onClose, onChanged, onCopied }: { onClose: () => void; onChanged: () => void; onCopied: (text: string) => void }) {
  const [status, setStatus] = useState<TwoFactorStatus | null>(null);
  const [view, setView] = useState<TwoFactorView>({ kind: "list" });
  const [password, setPassword] = useState("");
  const [auth, setAuth] = useState<AuthenticatorSetup | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [mail, setMail] = useState<EmailTwoFactorSetup | null>(null);
  const [address, setAddress] = useState("");
  const [sent, setSent] = useState(false);
  const [code, setCode] = useState("");
  const [recovery, setRecovery] = useState<string | null>(null);
  const { busy, error, run, clear } = useAction();

  const load = () => invoke<TwoFactorStatus>("two_factor_status").then(setStatus);
  useEffect(() => {
    load().catch(() => setStatus({ authenticator: false, email: false, others: [] }));
  }, []);

  // The QR code is drawn locally: the authenticator's secret does not go
  // outwards.
  useEffect(() => {
    if (!auth) return;
    QRCode.toDataURL(auth.otpauth, { margin: 1, width: 176, color: { dark: "#000000ff", light: "#ffffffff" } })
      .then(setQr)
      .catch(() => setQr(null));
  }, [auth]);

  const back = () => {
    setView({ kind: "list" });
    setPassword("");
    setCode("");
    setAuth(null);
    setQr(null);
    setMail(null);
    setSent(false);
    setRecovery(null);
    clear();
  };
  const finish = (s: TwoFactorStatus) => {
    setStatus(s);
    onChanged();
    back();
  };

  const title =
    view.kind === "list"
      ? t("settings.twofactor.title")
      : view.kind === "auth"
        ? t("settings.twofactor.authenticator")
        : view.kind === "email"
          ? t("settings.twofactor.email")
          : view.kind === "recovery"
            ? t("settings.twofactor.recovery")
            : t("settings.twofactor.disableTitle", { name: view.name });

  // What the main button does at the current step. One calculation, one
  // footer.
  let primary: { label: string; ready: boolean; onClick: () => void } | null = null;
  if (view.kind === "auth") {
    primary = auth
      ? {
          label: t("settings.twofactor.enable"),
          ready: Boolean(code) && !busy,
          onClick: () =>
            void run(async () => finish(await invoke<TwoFactorStatus>("two_factor_authenticator_enable", { masterPassword: password, key: auth.key, token: code }))),
        }
      : {
          label: t("action.continue"),
          ready: Boolean(password) && !busy,
          onClick: () => void run(async () => setAuth(await invoke<AuthenticatorSetup>("two_factor_authenticator_setup", { masterPassword: password }))),
        };
  } else if (view.kind === "email") {
    primary = mail
      ? {
          label: t("settings.twofactor.enable"),
          ready: Boolean(code) && sent && !busy,
          onClick: () =>
            void run(async () => finish(await invoke<TwoFactorStatus>("two_factor_email_enable", { masterPassword: password, email: address, token: code }))),
        }
      : {
          label: t("action.continue"),
          ready: Boolean(password) && !busy,
          onClick: () =>
            void run(async () => {
              const s = await invoke<EmailTwoFactorSetup>("two_factor_email_setup", { masterPassword: password });
              setMail(s);
              setAddress(s.email);
            }),
        };
  } else if (view.kind === "recovery") {
    primary = recovery
      ? null
      : {
          label: t("action.show"),
          ready: Boolean(password) && !busy,
          onClick: () => void run(async () => setRecovery(await invokeSecret("two_factor_recovery_code", { masterPassword: password }))),
        };
  } else if (view.kind === "disable") {
    const provider = view.provider;
    primary = {
      label: t("settings.twofactor.disable"),
      ready: Boolean(password) && !busy,
      onClick: () => void run(async () => finish(await invoke<TwoFactorStatus>("two_factor_disable", { masterPassword: password, provider }))),
    };
  }

  return (
    <Modal
      title={title}
      onClose={onClose}
      onSubmit={primary?.ready ? primary.onClick : undefined}
      footer={
        view.kind === "list" ? undefined : (
          <>
            <button type="button" className="btn" onClick={back}>
              {t("action.back")}
            </button>
            {primary && (
              <button type="button" className={`btn ${view.kind === "disable" ? "danger" : "primary"}`} disabled={!primary.ready} onClick={primary.onClick}>
                {busy ? t("action.saving") : primary.label}
              </button>
            )}
          </>
        )
      }
    >
      {view.kind === "list" && (
        <>
          <p className="hint">{t("settings.twofactor.body")}</p>
          {status ? (
            <Rows>
              <Row title={t("settings.twofactor.authenticator")} hint={<Chip on={status.authenticator}>{status.authenticator ? t("settings.twofactor.on") : t("settings.twofactor.off")}</Chip>}>
                {status.authenticator ? (
                  <button type="button" className="btn" onClick={() => setView({ kind: "disable", provider: 0, name: t("settings.twofactor.authenticator") })}>
                    {t("settings.twofactor.disable")}
                  </button>
                ) : (
                  <button type="button" className="btn primary" onClick={() => setView({ kind: "auth" })}>
                    {t("settings.twofactor.setUp")}
                  </button>
                )}
              </Row>
              <Row title={t("settings.twofactor.email")} hint={<Chip on={status.email}>{status.email ? t("settings.twofactor.on") : t("settings.twofactor.off")}</Chip>}>
                {status.email ? (
                  <button type="button" className="btn" onClick={() => setView({ kind: "disable", provider: 1, name: t("settings.twofactor.email") })}>
                    {t("settings.twofactor.disable")}
                  </button>
                ) : (
                  <button type="button" className="btn" onClick={() => setView({ kind: "email" })}>
                    {t("settings.twofactor.setUp")}
                  </button>
                )}
              </Row>
              {status.others.map((o) => (
                <Row key={o.provider} title={o.name} hint={<Chip on>{t("settings.twofactor.onElsewhere")}</Chip>}>
                  <button type="button" className="btn" onClick={() => setView({ kind: "disable", provider: o.provider, name: o.name })}>
                    {t("settings.twofactor.disable")}
                  </button>
                </Row>
              ))}
              <Row title={t("settings.twofactor.recovery")} hint={t("settings.twofactor.recoveryHint")}>
                <button type="button" className="btn" onClick={() => setView({ kind: "recovery" })}>
                  {t("action.show")}
                </button>
              </Row>
            </Rows>
          ) : (
            <p className="hint">{t("settings.profile.loading")}</p>
          )}
        </>
      )}

      {view.kind === "auth" && !auth && <PasswordStep value={password} onChange={setPassword} body={t("settings.twofactor.authBody")} />}
      {view.kind === "auth" && auth && (
        <>
          <p className="hint">{t("settings.twofactor.scan")}</p>
          <div className="qr-row">
            {qr ? <img className="qr" src={qr} alt={t("settings.twofactor.qrAlt")} width={176} height={176} /> : <span className="qr placeholder" />}
            <div className="qr-side">
              <span className="hint">{t("settings.twofactor.key")}</span>
              <span className="fingerprint">
                {/* In fours, as Bitwarden itself shows it: that way the secret
                    is checked by eye and typed without losing one's place. */}
                <span className="mono">{auth.key.match(/.{1,4}/g)?.join(" ") ?? auth.key}</span>
                <CopyButton value={auth.key} onCopied={onCopied} title={t("action.copy")} />
              </span>
            </div>
          </div>
          <div className="field">
            <label>{t("settings.twofactor.code")}</label>
            <input value={code} onChange={(e) => setCode(e.target.value)} aria-label={t("settings.twofactor.code")} inputMode="numeric" autoFocus spellCheck={false} />
          </div>
        </>
      )}

      {view.kind === "email" && !mail && <PasswordStep value={password} onChange={setPassword} body={t("settings.twofactor.emailBody")} />}
      {view.kind === "email" && mail && (
        <>
          <div className="field">
            <label>{t("settings.twofactor.emailAddress")}</label>
            <div className="row-actions inline">
              <input value={address} onChange={(e) => setAddress(e.target.value)} aria-label={t("settings.twofactor.emailAddress")} spellCheck={false} autoCapitalize="off" inputMode="email" />
              <button
                type="button"
                className="btn"
                disabled={!address || busy}
                onClick={() =>
                  void run(async () => {
                    await invoke("two_factor_email_send", { masterPassword: password, email: address });
                    setSent(true);
                  })
                }
              >
                {sent ? t("twofactor.resendEmail") : t("settings.twofactor.sendCode")}
              </button>
            </div>
          </div>
          <div className="field">
            <label>{t("settings.twofactor.code")}</label>
            <input value={code} onChange={(e) => setCode(e.target.value)} aria-label={t("settings.twofactor.code")} inputMode="numeric" spellCheck={false} disabled={!sent} />
          </div>
        </>
      )}

      {view.kind === "recovery" && !recovery && <PasswordStep value={password} onChange={setPassword} body={t("settings.twofactor.recoveryBody")} />}
      {view.kind === "recovery" && recovery && (
        <>
          <p className="hint">{t("settings.twofactor.recoveryShown")}</p>
          <div className="fingerprint big">
            <span className="mono">{recovery}</span>
            <CopyButton value={recovery} onCopied={onCopied} title={t("action.copy")} />
          </div>
        </>
      )}

      {view.kind === "disable" && <PasswordStep value={password} onChange={setPassword} body={t("settings.twofactor.disableBody", { name: view.name })} />}

      {error && <Alert message={error} />}
    </Modal>
  );
}

/// The "confirm with the master password" step: an explanation and one field.
function PasswordStep({ value, onChange, body }: { value: string; onChange: (v: string) => void; body: string }) {
  return (
    <>
      <p className="hint">{body}</p>
      <div className="field">
        <label>{t("settings.confirm.password")}</label>
        <PasswordInput value={value} onChange={onChange} autoFocus ariaLabel={t("settings.confirm.password")} />
      </div>
    </>
  );
}

function KdfModal({ kdf, onClose, onChanged, hold }: { kdf: KdfInfo; onClose: () => void; onChanged: () => void; hold: (on: boolean) => void }) {
  useHold(hold);
  const [kind, setKind] = useState<KdfInfo["kind"]>(kdf.kind);
  const [iterations, setIterations] = useState(kdf.kind === "pbkdf2" ? kdf.iterations : 3);
  const [memory, setMemory] = useState(kdf.kind === "argon2id" ? kdf.memory_mib : 64);
  const [parallelism, setParallelism] = useState(kdf.kind === "argon2id" ? kdf.parallelism : 4);
  const [password, setPassword] = useState("");
  const { busy, error, run } = useAction();
  const flow = useLoginFlow(() => {
    onChanged();
    onClose();
  });

  // The limits are Vaultwarden's: below them the server refuses, above them a
  // login takes seconds. The daemon also refuses the very parameters that are
  // already set — the button does not light up for those.
  const valid =
    kind === "pbkdf2"
      ? iterations >= 100_000 && iterations <= 2_000_000
      : iterations >= 1 && iterations <= 10 && memory >= 15 && memory <= 1024 && parallelism >= 1 && parallelism <= 16;
  const next: KdfInfo = kind === "pbkdf2" ? { kind, iterations } : { kind, iterations, memory_mib: memory, parallelism };
  const same = JSON.stringify(next) === JSON.stringify(kdf);
  const ready = valid && !same && Boolean(password) && !busy;
  const submit = () => {
    if (!ready) return;
    void run(async () => flow.handle(await invoke<LoginReply>("account_change_kdf", { masterPassword: password, kdf: next })));
  };

  if (flow.step) {
    return (
      <Modal title={t("twofactor.title")} onClose={onClose}>
        <p className="hint">{t("settings.twofactor.afterChange")}</p>
        {flow.step}
      </Modal>
    );
  }

  const num = (v: number, set: (n: number) => void, min: number, max: number, step = 1) => (
    <input type="number" value={v} min={min} max={max} step={step} onChange={(e) => set(Number(e.target.value))} className="mono" />
  );

  return (
    <Modal
      title={t("settings.kdf.title")}
      onClose={onClose}
      onSubmit={submit}
      footer={
        <button type="button" className="btn primary" disabled={!ready} onClick={submit}>
          {busy ? t("action.saving") : t("settings.kdf.action")}
        </button>
      }
    >
      <p className="hint">{t("settings.kdf.body")}</p>
      <Segmented
        value={kind}
        options={[
          { id: "pbkdf2", label: "PBKDF2 SHA-256" },
          { id: "argon2id", label: "Argon2id" },
        ]}
        onChange={(k) => {
          setKind(k);
          setIterations(k === "pbkdf2" ? 600_000 : 3);
        }}
      />
      {kind === "pbkdf2" ? (
        <div className="field">
          <label>{t("settings.kdf.iterations")}</label>
          {num(iterations, setIterations, 100_000, 2_000_000, 1000)}
          <span className="hint">{t("settings.kdf.iterationsHint")}</span>
        </div>
      ) : (
        <div className="pair three">
          <div className="field">
            <label>{t("settings.kdf.iterations")}</label>
            {num(iterations, setIterations, 1, 10)}
          </div>
          <div className="field">
            <label>{t("settings.kdf.memory")}</label>
            {num(memory, setMemory, 15, 1024, 1)}
          </div>
          <div className="field">
            <label>{t("settings.kdf.parallelism")}</label>
            {num(parallelism, setParallelism, 1, 16)}
          </div>
        </div>
      )}
      <Alert tone="warn" message={t("settings.kdf.warn")} />
      <div className="field">
        <label>{t("settings.confirm.password")}</label>
        <PasswordInput value={password} onChange={setPassword} ariaLabel={t("settings.confirm.password")} />
      </div>
      {error && <Alert message={error} />}
    </Modal>
  );
}

function deviceIcon(kind: string): string {
  const k = kind.toLowerCase();
  if (k.includes("mobile") || k.includes("android") || k.includes("ios")) return "mobile";
  if (k.includes("browser") || k.includes("extension") || k.includes("web")) return "globe";
  if (k.includes("cli") || k.includes("sdk")) return "terminal";
  return "desktop";
}

/// The devices with no actions: Vaultwarden has no request to throw out a
/// single one, only "all at once" — and that lives in the account's danger
/// zone.
function DevicesModal({ onClose, onDeauthorize }: { onClose: () => void; onDeauthorize: () => void }) {
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    invoke<Device[]>("devices").then(setDevices).catch((e) => setError(String(e)));
  }, []);
  const sorted = devices ? [...devices].sort((a, b) => Number(b.current) - Number(a.current) || (b.last_active ?? "").localeCompare(a.last_active ?? "")) : null;

  return (
    <Modal
      title={t("settings.devices")}
      onClose={onClose}
      footer={
        <>
          <span className="hint">{t("settings.devices.noSingle")}</span>
          <button type="button" className="btn danger" onClick={onDeauthorize}>
            {t("settings.deauthorize")}
          </button>
        </>
      }
    >
      <p className="hint">{t("settings.devices.body")}</p>
      {error && <Alert message={error} />}
      {sorted && sorted.length === 0 && <p className="hint">{t("settings.devices.none")}</p>}
      {sorted && (
        <div className="device-list">
          {sorted.map((d) => (
            <div key={d.id} className={`device ${d.current ? "current" : ""}`}>
              <Icon name={deviceIcon(d.kind)} size={16} />
              <span className="device-text">
                <b>{d.name || d.kind}</b>
                <span className="hint">
                  {d.kind}
                  {d.created ? ` · ${t("settings.devices.created", { when: fmtWhen(d.created) })}` : ""}
                  {d.identifier ? ` · ${d.identifier.slice(0, 8)}` : ""}
                </span>
              </span>
              {d.current && <Chip on>{t("settings.devices.this")}</Chip>}
            </div>
          ))}
        </div>
      )}
    </Modal>
  );
}

function ExportModal({ onClose, onCopied }: { onClose: () => void; onCopied: (text: string) => void }) {
  const [format, setFormat] = useState<ExportFormat>("json");
  const [password, setPassword] = useState("");
  const { busy, error, run } = useAction();
  const ready = Boolean(password) && !busy;
  const submit = () => {
    if (!ready) return;
    void run(async () => {
      const path = await invoke<string | null>("export_vault", { masterPassword: password, format });
      // `null` means the dialogue was closed: nothing was written, and this
      // one stays.
      if (path === null) return;
      onCopied(t("settings.export.saved", { path }));
      onClose();
    });
  };
  return (
    <Modal
      title={t("settings.export.title")}
      onClose={onClose}
      onSubmit={submit}
      footer={
        <button type="button" className="btn primary" disabled={!ready} onClick={submit}>
          {busy ? t("action.saving") : t("settings.export.save")}
        </button>
      }
    >
      <p className="hint">{t("settings.export.body")}</p>
      <Segmented
        value={format}
        options={[
          { id: "json", label: "JSON" },
          { id: "csv", label: "CSV" },
        ]}
        onChange={setFormat}
      />
      <span className="hint">{format === "json" ? t("settings.export.jsonHint") : t("settings.export.csvHint")}</span>
      <Alert tone="warn" message={t("settings.export.warn")} />
      <div className="field">
        <label>{t("settings.confirm.password")}</label>
        <PasswordInput value={password} onChange={setPassword} autoFocus ariaLabel={t("settings.confirm.password")} />
      </div>
      {error && <Alert message={error} />}
    </Modal>
  );
}

/// The dangerous actions on an account: one confirmation by master password
/// for each.
function ConfirmModal({ what, onClose, onChanged, hold }: { what: "deauthorize" | "purge" | "delete"; onClose: () => void; onChanged: () => void; hold: (on: boolean) => void }) {
  useHold(hold);
  const [password, setPassword] = useState("");
  const { busy, error, run } = useAction();
  const flow = useLoginFlow(() => {
    onChanged();
    onClose();
  });
  const titles: Record<typeof what, Key> = { deauthorize: "settings.deauthorize", purge: "settings.purge", delete: "settings.deleteAccount" };
  const bodies: Record<typeof what, Key> = { deauthorize: "settings.deauthorize.body", purge: "settings.purge.body", delete: "settings.deleteAccount.body" };
  const actions: Record<typeof what, Key> = { deauthorize: "settings.deauthorize.action", purge: "settings.purge.action", delete: "settings.deleteAccount.action" };
  const ready = Boolean(password) && !busy;
  const submit = () => {
    if (!ready) return;
    void run(async () => {
      if (what === "deauthorize") {
        flow.handle(await invoke<LoginReply>("account_deauthorize", { masterPassword: password }));
      } else {
        await invoke(what === "purge" ? "account_purge" : "account_delete", { masterPassword: password });
        onChanged();
        onClose();
      }
    });
  };

  if (flow.step) {
    return (
      <Modal title={t("twofactor.title")} onClose={onClose}>
        <p className="hint">{t("settings.twofactor.afterChange")}</p>
        {flow.step}
      </Modal>
    );
  }

  return (
    <Modal
      title={t(titles[what])}
      onClose={onClose}
      onSubmit={submit}
      footer={
        <button type="button" className={`btn ${what === "deauthorize" ? "warn" : "danger"}`} disabled={!ready} onClick={submit}>
          {busy ? t("action.saving") : t(actions[what])}
        </button>
      }
    >
      <PasswordStep value={password} onChange={setPassword} body={t(bodies[what])} />
      {error && <Alert message={error} />}
    </Modal>
  );
}

// ── The daemon's settings ────────────────────────────────────────────────

/// The settings the daemon governs: automatic locking, the clipboard, the
/// agent. They are saved at once — an "Apply" for something this small only
/// gets in the way.
function useSettings(onSettingsChanged?: (s: AppSettings) => void) {
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    invoke<AppSettings>("get_settings").then(setSettings).catch((e) => setError(String(e)));
  }, []);

  const patch = async (next: Partial<AppSettings>) => {
    if (!settings) return;
    const merged = { ...settings, ...next };
    setSettings(merged);
    setError(null);
    try {
      const stored = await invoke<AppSettings>("set_settings", { settings: merged });
      setSettings(stored);
      onSettingsChanged?.(stored);
      // The language and the window are not the daemon's business: they are
      // applied here and at once.
      setLanguage(stored.language);
      invoke("apply_window_prefs").catch(() => {});
      setSaved(true);
      setTimeout(() => setSaved(false), 1400);
    } catch (e) {
      setError(String(e));
      // What the daemon actually holds is put back: a value that was not
      // accepted must not be shown as if it had been.
      invoke<AppSettings>("get_settings").then(setSettings).catch(() => {});
    }
  };

  return { settings, error, saved, patch };
}

const LOCK_CHOICES: LockTimeout[] = [
  { kind: "minutes", minutes: 1 },
  { kind: "minutes", minutes: 5 },
  { kind: "minutes", minutes: 15 },
  { kind: "minutes", minutes: 60 },
  { kind: "on_restart" },
  { kind: "never" },
];

function lockLabel(v: LockTimeout): string {
  if (v.kind === "minutes") return t("settings.lock.minutes", { n: v.minutes });
  return v.kind === "never" ? t("settings.lock.never") : t("settings.lock.onRestart");
}

const CLIPBOARD_CHOICES = [0, 10, 30, 60, 120, 300];
const GRACE_CHOICES = [0, 60, 300, 900, 3600];

function clipboardLabel(sec: number): string {
  if (sec === 0) return t("settings.clipboard.never");
  return sec < 60 ? t("settings.clipboard.seconds", { n: sec }) : t("settings.clipboard.minutes", { n: Math.round(sec / 60) });
}

function graceLabel(sec: number): string {
  if (sec === 0) return t("settings.grace.always");
  return sec < 60 ? t("settings.clipboard.seconds", { n: sec }) : t("settings.clipboard.minutes", { n: Math.round(sec / 60) });
}

/// An honest caption under "Touch ID": the trouble first, when there is any.
function touchIdHint(remembered: boolean, bio: BiometricState | null): string {
  if (bio && !bio.available) return t("biometric.broken", { why: bio.problem ?? "" });
  if (bio?.last_failure) return t("biometric.lastFailure", { why: bio.last_failure });
  return remembered ? t("biometric.on") : t("biometric.off");
}

function SecurityTab({ status, onChanged, onSettingsChanged }: { status: Status; onChanged: () => void; onSettingsChanged?: (s: AppSettings) => void }) {
  // The sensor's state is asked of the daemon: "set up" is about the
  // remembered password, and whether Touch ID works just now only the system
  // knows.
  const [bio, setBio] = useState<BiometricState | null>(null);
  useEffect(() => {
    invoke<BiometricState>("biometric_state").then(setBio).catch(() => setBio(null));
  }, [status.biometric]);

  const { settings, patch, error: settingsError } = useSettings(onSettingsChanged);
  const [password, setPassword] = useState("");
  const [touchIdOpen, setTouchIdOpen] = useState(false);
  const [pinOpen, setPinOpen] = useState(false);
  const { busy, error, run } = useAction(onChanged);

  return (
    <>
      <Section title={t("settings.security.unlock")} tone="mint">
        <Rows>
          <Row title="Touch ID" hint={touchIdHint(status.biometric, bio)}>
            {status.biometric ? (
              <button type="button" className="btn" disabled={busy} onClick={() => void run(() => invoke("biometric_forget"))}>
                {t("biometric.forget")}
              </button>
            ) : (
              <button type="button" className="btn primary" onClick={() => setTouchIdOpen(true)}>
                {t("biometric.enable")}
              </button>
            )}
          </Row>
          {settings && (
            <>
              <Row title={t("settings.touchIdLaunch")}>
                <Toggle on={settings.touch_id_on_launch} onChange={(v) => void patch({ touch_id_on_launch: v })} />
              </Row>
              <Row title={t("settings.touchIdSecrets")} hint={t("settings.touchIdSecretsHint")}>
                <Toggle
                  on={settings.touch_id_for_secrets}
                  onChange={(v) => void patch({ touch_id_for_secrets: v })}
                />
              </Row>
              <Row title={t("settings.grace")} hint={t("settings.graceHint")}>
                <div className="control">
                  <Picker
                    value={String(settings.biometric_grace_seconds)}
                    placeholder={graceLabel(settings.biometric_grace_seconds)}
                    options={GRACE_CHOICES.map((sec) => ({ id: String(sec), label: graceLabel(sec) }))}
                    onChange={(id) => void patch({ biometric_grace_seconds: Number(id) })}
                  />
                </div>
              </Row>
            </>
          )}
          <Row title={t("settings.pin")} hint={status.pin ? t("settings.pin.on") : t("settings.pin.off")}>
            <Toggle
              on={status.pin}
              onChange={(v) => {
                if (v) setPinOpen(true);
                else void run(() => invoke("pin_clear"));
              }}
            />
          </Row>
        </Rows>
        {error && <Alert message={error} />}
      </Section>

      <BrowserExtensions />

      {settings && (
        <Section title={t("settings.security.timeout")} tone="amber">
          <Rows>
            <Row title={t("settings.lock")} hint={t("settings.lockHint")}>
              <div className="control">
                <Picker
                  value={JSON.stringify(settings.lock_timeout)}
                  placeholder={lockLabel(settings.lock_timeout)}
                  options={LOCK_CHOICES.map((v) => ({ id: JSON.stringify(v), label: lockLabel(v) }))}
                  onChange={(id) => void patch({ lock_timeout: JSON.parse(id) as LockTimeout })}
                />
              </div>
            </Row>
            <Row title={t("settings.lockAction")} hint={settings.lock_action === "logout" ? t("settings.lockAction.logoutHint") : t("settings.lockAction.lockHint")}>
              <div className="control">
                <Segmented
                  value={settings.lock_action}
                  options={[
                    { id: "lock", label: t("settings.lockAction.lock") },
                    { id: "logout", label: t("settings.lockAction.logout") },
                  ]}
                  onChange={(v) => void patch({ lock_action: v })}
                />
              </div>
            </Row>
            <Row title={t("settings.security.lock")} hint={t("settings.security.lockHint")}>
              <button type="button" className="btn" disabled={busy} onClick={() => void run(() => invoke("vault_lock"))}>
                <Icon name="lock" size={13} />
                {t("action.lock")}
              </button>
            </Row>
          </Rows>
        </Section>
      )}
      {settingsError && <Alert message={settingsError} />}

      {touchIdOpen && !status.biometric && (
        <Modal
          title={t("biometric.enable")}
          onClose={() => setTouchIdOpen(false)}
          onSubmit={() =>
            void run(async () => {
              await invoke("biometric_remember", { password });
              setPassword("");
              setTouchIdOpen(false);
            })
          }
          footer={
            <button
              type="button"
              className="btn primary"
              disabled={busy || !password}
              onClick={() =>
                void run(async () => {
                  await invoke("biometric_remember", { password });
                  setPassword("");
                  setTouchIdOpen(false);
                })
              }
            >
              {busy ? t("action.saving") : t("biometric.remember")}
            </button>
          }
        >
          <div className="field">
            <label>{t("biometric.password")}</label>
            <PasswordInput value={password} onChange={setPassword} autoFocus ariaLabel={t("biometric.password")} />
          </div>
          {error && <Alert message={error} />}
        </Modal>
      )}

      {pinOpen && !status.pin && (
        <PinModal
          onClose={() => setPinOpen(false)}
          onChanged={() => {
            setPinOpen(false);
            onChanged();
          }}
        />
      )}
    </>
  );
}

/// A PIN is a short code in place of the master password. The master password
/// is asked for once: the daemon encrypts it with a key made from the PIN and
/// keeps it on disk.
function PinModal({ onClose, onChanged }: { onClose: () => void; onChanged: () => void }) {
  const [pin, setPin] = useState("");
  const [again, setAgain] = useState("");
  const [password, setPassword] = useState("");
  const { busy, error, run } = useAction();
  const tooShort = pin !== "" && pin.length < 4;
  const mismatch = again !== "" && again !== pin;
  const ready = pin.length >= 4 && pin === again && Boolean(password) && !busy;
  const submit = () => {
    if (!ready) return;
    void run(async () => {
      await invoke("pin_set", { pin, masterPassword: password });
      onChanged();
    });
  };
  return (
    <Modal
      title={t("settings.pin.title")}
      onClose={onClose}
      onSubmit={submit}
      footer={
        <button type="button" className="btn primary" disabled={!ready} onClick={submit}>
          {busy ? t("action.saving") : t("settings.pin.action")}
        </button>
      }
    >
      <p className="hint">{t("settings.pin.body")}</p>
      <div className="pair">
        <div className="field">
          <label>{t("settings.pin.new")}</label>
          <PasswordInput value={pin} onChange={setPin} autoFocus inputMode="numeric" ariaLabel={t("settings.pin.new")} />
          {tooShort && <span className="hint warn">{t("settings.pin.short")}</span>}
        </div>
        <div className="field">
          <label>{t("settings.pin.again")}</label>
          <PasswordInput value={again} onChange={setAgain} inputMode="numeric" ariaLabel={t("settings.pin.again")} />
          {mismatch && <span className="hint warn">{t("settings.pin.mismatch")}</span>}
        </div>
      </div>
      <div className="field">
        <label>{t("settings.confirm.password")}</label>
        <PasswordInput value={password} onChange={setPassword} ariaLabel={t("settings.confirm.password")} />
      </div>
      {error && <Alert message={error} />}
    </Modal>
  );
}

function AppTab({ onSettingsChanged, part }: { onSettingsChanged?: (s: AppSettings) => void; part: "preferences" | "app" }) {
  const { settings, error, saved, patch } = useSettings(onSettingsChanged);
  const [interfaceError, setInterfaceError] = useState<string | null>(null);
  if (!settings) return error ? <Alert message={error} /> : null;

  return (
    <>
      {part === "preferences" && (
      <Section title={t("settings.behaviour")} tone="mint">
        <Rows>
          <Row title={t("settings.clipboard")} hint={t("settings.security.clipboardHint")}>
            <div className="control">
              <Picker
                value={String(settings.clipboard_clear_seconds)}
                placeholder={clipboardLabel(settings.clipboard_clear_seconds)}
                options={CLIPBOARD_CHOICES.map((sec) => ({ id: String(sec), label: clipboardLabel(sec) }))}
                onChange={(id) => void patch({ clipboard_clear_seconds: Number(id) })}
              />
            </div>
          </Row>
          <Row title={t("settings.hideOnCopy")} hint={t("settings.hideOnCopyHint")}>
            <Toggle on={settings.hide_on_copy} onChange={(v) => void patch({ hide_on_copy: v })} />
          </Row>
          <Row title={t("settings.icons")} hint={t("settings.iconsHint")}>
            <Toggle on={settings.show_website_icons} onChange={(v) => void patch({ show_website_icons: v })} />
          </Row>
          {/* A choice of its own, apart from the menu bar: the two together
              decide what the close button leaves behind. */}
          <Row title={t("settings.keepInDock")} hint={t("settings.keepInDockHint")}>
            <Toggle on={settings.keep_in_dock} onChange={(v) => void patch({ keep_in_dock: v })} />
          </Row>
        </Rows>
      </Section>
      )}

      {part === "app" && (
      <Section title={t("settings.tab.app")} tone="amber">
        <Rows>
          <Row title={t("settings.keepInTray")} hint={t("settings.keepInTrayHint")}>
            <Toggle on={settings.keep_in_tray} onChange={(v) => void patch({ keep_in_tray: v })} />
          </Row>
          <Row title={t("settings.startOnLogin")} hint={t("settings.startOnLoginHint")}>
            <Toggle on={settings.start_on_login} onChange={(v) => void patch({ start_on_login: v })} />
          </Row>
          <Row title={t("settings.screenCapture")} hint={t("settings.screenCaptureHint")}>
            <Toggle on={settings.allow_screen_capture} onChange={(v) => void patch({ allow_screen_capture: v })} />
          </Row>
          {/* Saved and the window reloaded into the other page at once. */}
          <Row title={t("settings.newInterface")} hint={t("settings.newInterfaceHint")}>
            <Toggle
              on={settings.interface === "new"}
              onChange={(v) => {
                setInterfaceError(null);
                invoke("set_interface", { ui: v ? "new" : "old" }).catch((e) => setInterfaceError(String(e)));
              }}
            />
          </Row>
        </Rows>
      </Section>
      )}

      {part === "preferences" && (
      <Section title={t("settings.appearance")} tone="orange">
        <Rows>
          <Row title={t("settings.theme")}>
            <div className="control">
              <Picker
                value={settings.theme}
                placeholder={t(`settings.theme.${settings.theme}` as Key)}
                options={(["system", "dark", "light"] as const).map((v) => ({
                  id: v,
                  label: t(`settings.theme.${v}` as Key),
                }))}
                onChange={(id) => void patch({ theme: id as AppSettings["theme"] })}
              />
            </div>
          </Row>
          <Row title={t("settings.accent")} hint={t("settings.accentHint")}>
            <PalettePicker value={settings.accent_color} theme={settings.theme} onChange={(color) => void patch({ accent_color: color })} />
          </Row>
          <Row title={t("settings.language")} hint={t("settings.languageHint")}>
            <div className="control">
              <Picker
                value={settings.language}
                placeholder={settings.language === "auto" ? t("settings.language.auto") : settings.language === "ru" ? "Русский" : "English"}
                options={[
                  { id: "auto", label: t("settings.language.auto") },
                  { id: "ru", label: "Русский" },
                  { id: "en", label: "English" },
                ]}
                onChange={(id) => void patch({ language: id as AppSettings["language"] })}
              />
            </div>
          </Row>
        </Rows>
      </Section>
      )}

      {saved && <div className="hint">{t("settings.saved")}</div>}
      {error && <Alert message={error} />}
      {interfaceError && <Alert message={interfaceError} />}
    </>
  );
}

function AboutTab({ status }: { status: Status }) {
  return (
    <Section title={t("settings.tab.about")}>
      <Field label={t("settings.about.version")} value={status.version} />
      <Field label={t("settings.about.daemon")} value={t("settings.about.alive")} />
      <Field label={t("settings.about.source")} value={status.source} />
      <Field label={t("settings.about.log")} value="~/.keyward/daemon.log" />
    </Section>
  );
}
