/// An item's fields by its kind — one set for both forms.
///
/// Creating and editing used to know about logins alone: a name, a password, a
/// key for one-time codes. A card and an identity have sets of their own, and
/// they could be filled in only in somebody else's client. Now the set is one
/// and the same in both forms — otherwise they drift apart, as they once
/// already did.
import { useState } from "react";
import { Empty, Icon, Modal, Picker, Segmented, Suggest, Toggle } from "../ui";
import { t } from "../i18n";
import type { Key } from "../i18n";
import type { ItemKind } from "../types";
import { PasswordInput } from "../PasswordInput";
import { CardBrandMark, detectCardBrand } from "../CardBrand";

export type CardState = {
  cardholderName: string;
  number: string;
  brand: string;
  expMonth: string;
  expYear: string;
  code: string;
};

export type IdentityState = {
  title: string;
  firstName: string;
  middleName: string;
  lastName: string;
  username: string;
  company: string;
  email: string;
  phone: string;
  address1: string;
  address2: string;
  address3: string;
  city: string;
  state: string;
  postalCode: string;
  country: string;
  ssn: string;
  passportNumber: string;
  licenseNumber: string;
};

export const EMPTY_CARD: CardState = {
  cardholderName: "",
  number: "",
  brand: "",
  expMonth: "",
  expYear: "",
  code: "",
};

export const EMPTY_IDENTITY: IdentityState = {
  title: "",
  firstName: "",
  middleName: "",
  lastName: "",
  username: "",
  company: "",
  email: "",
  phone: "",
  address1: "",
  address2: "",
  address3: "",
  city: "",
  state: "",
  postalCode: "",
  country: "",
  ssn: "",
  passportNumber: "",
  licenseNumber: "",
};

/// The card brands Bitwarden offers as a list: free typing here only breeds
/// "Visa", "visa" and "VISA" in one vault.
const BRANDS = ["Visa", "Mastercard", "American Express", "Discover", "Diners Club", "JCB", "Maestro", "UnionPay", "RuPay", "Mir", "Other"];
const MONTHS = ["01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12"];
const TITLES = ["Mr", "Mrs", "Ms", "Mx", "Dr"];

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="field">
      <label>{label}</label>
      {children}
    </div>
  );
}

export function CardFields({
  value,
  onChange,
}: {
  value: CardState;
  onChange: (next: CardState) => void;
}) {
  const set = (patch: Partial<CardState>) => onChange({ ...value, ...patch });
  return (
    <>
      <Row label={t("card.holder")}>
        <input
          value={value.cardholderName}
          onChange={(e) => set({ cardholderName: e.target.value })}
          spellCheck={false}
        />
      </Row>
      <div className="pair">
        <Row label={t("card.number")}>
          <span className="card-number-input">
            <PasswordInput value={value.number} onChange={(v) => set({ number: v })} ariaLabel={t("card.number")} />
            <CardBrandMark brand={detectCardBrand(value.number, value.brand)} compact />
          </span>
        </Row>
        <Row label={t("card.brand")}>
          <Picker
            value={value.brand || null}
            placeholder={t("card.brandPick")}
            options={BRANDS.map((b) => ({ id: b, label: b }))}
            onChange={(id) => set({ brand: id })}
          />
        </Row>
      </div>
      <div className="pair">
        <Row label={t("card.expMonth")}>
          <Picker
            value={value.expMonth || null}
            placeholder={t("card.expMonthPick")}
            options={MONTHS.map((m) => ({ id: m, label: m }))}
            onChange={(id) => set({ expMonth: id })}
          />
        </Row>
        <Row label={t("card.expYear")}>
          <input
            value={value.expYear}
            onChange={(e) => set({ expYear: e.target.value })}
            aria-label={t("card.expYear")}
            placeholder="2029"
            spellCheck={false}
          />
        </Row>
      </div>
      <Row label={t("card.code")}>
        <PasswordInput value={value.code} onChange={(v) => set({ code: v })} ariaLabel={t("card.code")} />
      </Row>
    </>
  );
}

export function IdentityFields({
  value,
  onChange,
  logins = [],
}: {
  value: IdentityState;
  onChange: (next: IdentityState) => void;
  /// The emails and logins from the vault — for hints, as in the login's
  /// form.
  logins?: string[];
}) {
  const set = (patch: Partial<IdentityState>) => onChange({ ...value, ...patch });
  const text = (key: keyof IdentityState, label: Key, hidden = false) => (
    <Row label={t(label)}>
      {hidden ? (
        <PasswordInput value={value[key]} onChange={(v) => set({ [key]: v } as Partial<IdentityState>)} ariaLabel={t(label)} />
      ) : (
        <input
          value={value[key]}
          onChange={(e) => set({ [key]: e.target.value } as Partial<IdentityState>)}
          spellCheck={false}
        />
      )}
    </Row>
  );

  /// A field with hints — for the email and the login: the same three or four
  /// values as in the login items.
  const known = (key: "email" | "username", label: Key) => (
    <Row label={t(label)}>
      <Suggest
        value={value[key]}
        onChange={(v) => set({ [key]: v } as Partial<IdentityState>)}
        options={logins}
        label={t(label)}
        spellCheck={false}
      />
    </Row>
  );

  return (
    <>
      <h4 className="form-section">{t("who.personal")}</h4>
      <div className="pair">
        <Row label={t("who.title")}>
          <Picker
            value={value.title || null}
            placeholder={t("who.titlePick")}
            options={TITLES.map((x) => ({ id: x, label: x }))}
            onChange={(id) => set({ title: id })}
          />
        </Row>
        {text("firstName", "who.first")}
      </div>
      <div className="pair">
        {text("middleName", "who.middle")}
        {text("lastName", "who.last")}
      </div>
      <div className="pair">
        {known("username", "who.username")}
        {text("company", "who.company")}
      </div>

      <h4 className="form-section">{t("who.papers")}</h4>
      <div className="pair">
        {text("ssn", "who.ssn", true)}
        {text("passportNumber", "who.passport", true)}
      </div>
      {text("licenseNumber", "who.license")}

      <h4 className="form-section">{t("who.contact")}</h4>
      <div className="pair">
        {known("email", "who.email")}
        {text("phone", "who.phone")}
      </div>

      <h4 className="form-section">{t("who.address")}</h4>
      {text("address1", "who.address1")}
      <div className="pair">
        {text("address2", "who.address2")}
        {text("address3", "who.address3")}
      </div>
      <div className="pair">
        {text("city", "who.city")}
        {text("state", "who.state")}
      </div>
      <div className="pair">
        {text("postalCode", "who.postal")}
        {text("country", "who.country")}
      </div>
    </>
  );
}

/// The "favourite" star — where the official client puts it.
/*
  A login's fields — one order for creating and for editing.

  Each form used to lay them out its own way: when creating, the sites came
  before the key for one-time codes, when editing, after it, and the password
  generator was in only one of the two. The order here is one: what we log in
  with, where we log in, what we confirm with.
*/
/// The logins and emails already met with in the vault: an item's subtitle is
/// the login for a login and the email for an identity. No request of its own
/// to the daemon is needed.
export function knownLogins(items: { kind: string; subtitle: string | null }[]): string[] {
  const seen = new Set<string>();
  for (const i of items) {
    if (i.kind !== "login" && i.kind !== "identity") continue;
    const v = i.subtitle?.trim();
    if (v) seen.add(v);
  }
  return [...seen].sort((a, b) => a.localeCompare(b));
}

export function LoginFields({
  username,
  password,
  totp,
  uris,
  logins,
  onUsername,
  onPassword,
  onTotp,
  onUris,
  onReveal,
}: {
  username: string;
  /// `null`: kept as it is and not loaded into the window.
  password: string | null;
  totp: string | null;
  uris: string[];
  /// The logins and emails already met with in the vault — for hints.
  logins: string[];
  onUsername: (v: string) => void;
  onPassword: (v: string) => void;
  onTotp: (v: string) => void;
  onUris: (v: string[]) => void;
  /// Loads a kept secret into the form, on a press.
  onReveal?: (which: "password" | "totp") => Promise<void>;
}) {
  return (
    <>
      <div className="field">
        <label>{t("edit.username")}</label>
        {/* Hints from the items already there: a person has a few emails and
            logins and hundreds of items, and there is no point typing them
            again. */}
        <Suggest
          value={username}
          onChange={onUsername}
          options={logins}
          label={t("edit.username")}
          spellCheck={false}
        />
      </div>

      <div className="field">
        <label>{t("edit.password")}</label>
        {/* The generator lives inside the field rather than as a button
            beside it: the action belongs to the value, and a button standing
            next to it would read as a second field. */}
        {password === null ? (
          <LockedSecret onReveal={() => onReveal?.("password") ?? Promise.resolve()} onReplace={() => onPassword("")} />
        ) : (
          <PasswordInput value={password} onChange={onPassword} generate ariaLabel={t("edit.password")} />
        )}
      </div>

      <div className="field">
        <label>{t("edit.sites")}</label>
        {uris.map((u, i) => (
          // A lone field has no cross: there is nothing to take away, and a
          // button that does nothing is a deceit.
          // The wrapper is always the same one: with a single site there was
          // none, and the field ended up at its default width — 170 pixels
          // against the full width of the rest.
          <div className={`site-row${uris.length > 1 ? " with-inner" : ""}`} key={i}>
            <input
              value={u}
              onChange={(e) => onUris(uris.map((x, j) => (j === i ? e.target.value : x)))}
              aria-label={t("edit.site")}
              placeholder="https://example.com"
              spellCheck={false}
            />
            {uris.length > 1 && (
              <button
                type="button"
                className="inner"
                aria-label={t("edit.removeSite")}
                onClick={() => onUris(uris.filter((_, j) => j !== i))}
              >
                <Icon name="close" size={12} />
              </button>
            )}
          </div>
        ))}
        <button type="button" className="btn quiet small" onClick={() => onUris([...uris, ""])}>
          <Icon name="plus" size={12} />
          {t("edit.addSite")}
        </button>
      </div>

      <div className="field">
        <label>{t("edit.totp")}</label>
        {/* The key rather than the code: every future one-time code is
            counted from it, and it has no business being on the screen. */}
        {totp === null ? (
          <LockedSecret onReveal={() => onReveal?.("totp") ?? Promise.resolve()} onReplace={() => onTotp("")} />
        ) : (
          <PasswordInput value={totp} onChange={onTotp} ariaLabel={t("edit.totp")} placeholder="otpauth://…" />
        )}
      </div>
    </>
  );
}

/// The note is always the last field with a value.
export function NotesField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <div className="field">
      <label>{t("edit.notes")}</label>
      <textarea value={value} onChange={(e) => onChange(e.target.value)} rows={4} />
    </div>
  );
}

/*
  How an item behaves — one block at the end of the form.

  The switches used to stand in different corners: the favourite above the tabs,
  the password prompt below the note. Both answer one question ("how is this to
  be handled"), and keeping them apart meant making somebody hunt.
*/
export function Behaviour({
  favourite,
  onFavourite,
  reprompt,
  onReprompt,
}: {
  favourite: boolean;
  onFavourite: (v: boolean) => void;
  reprompt: boolean;
  onReprompt: (v: boolean) => void;
}) {
  return (
    <div className="form-block">
      <h4 className="form-section">{t("edit.behaviour")}</h4>
      <div className="between wrap-row">
        <span className="text">
          <b>{t("item.favourite")}</b>
          <span className="hint">{t("item.favouriteHint")}</span>
        </span>
        <Toggle on={favourite} onChange={onFavourite} />
      </div>
      <div className="between wrap-row">
        <span className="text">
          <b>{t("edit.reprompt")}</b>
          <span className="hint">{t("edit.repromptHint")}</span>
        </span>
        <Toggle on={reprompt} onChange={onReprompt} />
      </div>
    </div>
  );
}


export { Toggle };


/// A custom field in an edit. `was` is the name the field lies under on the
/// server: both a rename and a deletion are found by it.
export type Custom = {
  name: string;
  /// `null`: a hidden field kept as it is, not loaded into the window.
  value: string | null;
  kind: number;
  linkedId?: number | null;
  was: string;
};

/// The kinds of custom fields — all four Bitwarden has.
const KINDS = [
  { kind: 0, key: "text" },
  { kind: 1, key: "hidden" },
  { kind: 2, key: "checkbox" },
  { kind: 3, key: "linked" },
] as const;

export const KIND_KEY: Record<number, string> = { 0: "text", 1: "hidden", 2: "checkbox", 3: "linked" };

/// Where a linked field may point. The numbers are the same as in the official
/// client: they travel to the server as `linkedId`, and a numbering of our own
/// would make an item unreadable to the other clients.
const LINKS: Record<string, { id: number; key: string }[]> = {
  login: [
    { id: 100, key: "username" },
    { id: 101, key: "password" },
  ],
  card: [
    { id: 300, key: "cardholderName" },
    { id: 301, key: "expMonth" },
    { id: 302, key: "expYear" },
    { id: 303, key: "code" },
    { id: 304, key: "brand" },
    { id: 305, key: "number" },
  ],
  identity: [
    { id: 400, key: "title" },
    { id: 416, key: "firstName" },
    { id: 401, key: "middleName" },
    { id: 417, key: "lastName" },
    { id: 418, key: "fullName" },
    { id: 413, key: "username" },
    { id: 409, key: "company" },
    { id: 410, key: "email" },
    { id: 411, key: "phone" },
    { id: 402, key: "address1" },
    { id: 403, key: "address2" },
    { id: 404, key: "address3" },
    { id: 405, key: "city" },
    { id: 406, key: "state" },
    { id: 407, key: "postalCode" },
    { id: 408, key: "country" },
    { id: 412, key: "ssn" },
    { id: 414, key: "passportNumber" },
    { id: 415, key: "licenseNumber" },
  ],
};

/// Whether an item of this kind has fields that can be pointed at.
export function linkTargets(kind: ItemKind): { id: number; key: string }[] {
  return LINKS[kind] ?? [];
}

export function linkLabel(id: number | null | undefined): string {
  if (id === null || id === undefined) return t("edit.link.none");
  for (const list of Object.values(LINKS)) {
    const hit = list.find((l) => l.id === id);
    if (hit) return t(`edit.link.${hit.key}` as Key);
  }
  // A foreign number is not invented: it is shown as it is, so that the field
  // is not lost.
  return `#${id}`;
}

/// The editor of custom fields — one and the same when creating and when
/// editing.
export function CustomFields({
  kind,
  fields,
  onChange,
  reveal,
}: {
  kind: ItemKind;
  fields: Custom[];
  onChange: (next: Custom[]) => void;
  /// Loads a kept hidden field's value, by the name it had.
  reveal?: (was: string) => Promise<string>;
}) {
  const [adding, setAdding] = useState(false);
  const targets = linkTargets(kind);
  const patch = (i: number, p: Partial<Custom>) =>
    onChange(fields.map((x, j) => (j === i ? { ...x, ...p } : x)));

  const KINDS_PICK = KINDS.filter((k) => k.kind !== 3 || targets.length > 0);

  return (
    <>
      {fields.length === 0 ? (
        // The empty state is built on the same `Empty` as everywhere else in
        // the application: a heading, an explanation, and the action last.
        // There used to be two grey paragraphs of one rank here, and which of
        // them explained the emptiness and which told about kw- was anybody's
        // guess.
        <Empty
          icon="note"
          title={t("edit.customEmptyTitle")}
          body={t("edit.customEmpty")}
          action={
            <button type="button" className="btn primary" onClick={() => setAdding(true)}>
              <Icon name="plus" size={14} />
              {t("edit.addCustom")}
            </button>
          }
        />
      ) : (
        <>
          {/* One line per field rather than a table of boxes: the name reads
              as the value's caption, the kind is a mark at the start of the
              line, and the value takes the width that is left. The table's
              columns squeezed every value to a third of the window, and in a
              narrow one each field grew into a stack of three boxes. */}
          <div className="custom-list">
            {fields.map((f, i) => (
              <CustomRow
                key={`${f.was}:${i}`}
                field={f}
                kinds={KINDS_PICK}
                targets={targets}
                onPatch={(p) => patch(i, p)}
                onReveal={reveal ? async () => patch(i, { value: await reveal(f.was) }) : undefined}
                onRemove={() => onChange(fields.filter((_, j) => j !== i))}
              />
            ))}
          </div>

          {/* Adding is the list's last line rather than a bar above it: a new
              field appears where the button was pressed. */}
          <button type="button" className="btn custom-add" onClick={() => setAdding(true)}>
            <Icon name="plus" size={14} />
            {t("edit.addCustom")}
          </button>
          <span className="hint">{t("edit.customHint")}</span>
        </>
      )}

      {adding && (
        <AddField
          kind={kind}
          onClose={() => setAdding(false)}
          onAdd={(field) => {
            onChange([...fields, { ...field, was: "" }]);
            setAdding(false);
          }}
        />
      )}
    </>
  );
}

/// A secret the form keeps as it is without loading it: the window gets the
/// value only when asked to show it or to replace it. An edit of the name or
/// the sites then never brings the password into the webview at all — and a
/// failed load can no longer turn into an empty value that the save would
/// write over the real one.
export function LockedSecret({ onReveal, onReplace }: { onReveal: () => Promise<void>; onReplace: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const show = async () => {
    setBusy(true);
    setError(null);
    try {
      await onReveal();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="locked-secret">
      <span className="mono">••••••••</span>
      <span className="hint">{t("edit.secretKept")}</span>
      <span className="grow" />
      <button type="button" className="btn small" disabled={busy} onClick={() => void show()}>
        {t("edit.secretShow")}
      </button>
      <button type="button" className="btn small" disabled={busy} onClick={onReplace}>
        {t("edit.secretReplace")}
      </button>
      {error && <span className="locked-error" role="alert">{error}</span>}
    </div>
  );
}

/// How each kind of field is marked at the start of its line.
const KIND_ICON: Record<number, string> = { 0: "note", 1: "lock", 2: "check", 3: "route" };

/// One custom field as one line: the kind's mark, the name, the value, the
/// removal. The mark opens the choice of kind under the line — changing a
/// kind is rare, and a picker in every row took a quarter of its width.
function CustomRow({
  field: f,
  kinds,
  targets,
  onPatch,
  onReveal,
  onRemove,
}: {
  field: Custom;
  kinds: readonly { kind: number; key: string }[];
  targets: { id: number; key: string }[];
  onPatch: (p: Partial<Custom>) => void;
  onReveal?: () => Promise<void>;
  onRemove: () => void;
}) {
  const [kindOpen, setKindOpen] = useState(false);
  const kindKey = KIND_KEY[f.kind] ?? "text";
  const kindLabel = t(`edit.kind.${kindKey}` as Key);
  return (
    <div className={`custom-row kind-${kindKey} ${kindOpen ? "open" : ""}`}>
      <button
        type="button"
        className="custom-kind"
        aria-expanded={kindOpen}
        aria-label={t("edit.kindChange", { kind: kindLabel })}
        title={t("edit.kindChange", { kind: kindLabel })}
        onClick={() => setKindOpen((v) => !v)}
      >
        <Icon name={KIND_ICON[f.kind] ?? "note"} size={14} />
      </button>

      <input
        className="custom-name"
        value={f.name}
        onChange={(e) => onPatch({ name: e.target.value })}
        placeholder={t("edit.customName")}
        aria-label={t("edit.customName")}
        spellCheck={false}
      />

      <div className="custom-value">
        {f.kind === 2 ? (
          <span className="custom-flag">
            <Toggle on={f.value === "true"} onChange={(v) => onPatch({ value: v ? "true" : "false" })} />
          </span>
        ) : f.kind === 3 ? (
          // A linked field has no value of its own: it shows what lies in the
          // item's field, so the target is what is chosen.
          <Picker
            value={f.linkedId === null || f.linkedId === undefined ? "" : String(f.linkedId)}
            onChange={(v) => onPatch({ linkedId: v === "" ? null : Number(v) })}
            placeholder={t("edit.link.none")}
            options={targets.map((l) => ({ id: String(l.id), label: t(`edit.link.${l.key}` as Key) }))}
          />
        ) : f.value === null ? (
          <LockedSecret onReveal={onReveal ?? (async () => {})} onReplace={() => onPatch({ value: "" })} />
        ) : f.kind === 1 ? (
          <PasswordInput value={f.value ?? ""} onChange={(v) => onPatch({ value: v })} generate ariaLabel={t("edit.customValue")} placeholder={t("edit.customValue")} />
        ) : (
          <input
            value={f.value ?? ""}
            onChange={(e) => onPatch({ value: e.target.value })}
            placeholder={t("edit.customValue")}
            aria-label={t("edit.customValue")}
            spellCheck={false}
          />
        )}
      </div>

      <button
        type="button"
        className="btn icon-only custom-remove"
        aria-label={t("edit.removeCustom")}
        title={t("edit.removeCustom")}
        onClick={onRemove}
      >
        <Icon name="trash" size={13} />
      </button>

      {kindOpen && (
        <div className="custom-kinds">
          <Segmented
            value={String(f.kind)}
            onChange={(v) => {
              // A new kind starts empty: a password left over as a checkbox's
              // value, or text as a link, would mean nothing.
              const next = Number(v);
              if (next !== f.kind) onPatch({ kind: next, value: "", linkedId: next === 3 ? (targets[0]?.id ?? null) : null });
              setKindOpen(false);
            }}
            options={kinds.map((k) => ({ id: String(k.kind), label: t(`edit.kind.${k.key}` as Key) }))}
          />
        </div>
      )}
    </div>
  );
}

function AddField({
  kind,
  onClose,
  onAdd,
}: {
  kind: ItemKind;
  onClose: () => void;
  onAdd: (field: { name: string; value: string; kind: number; linkedId: number | null }) => void;
}) {
  const targets = linkTargets(kind);
  const [pick, setPick] = useState(0);
  const [name, setName] = useState("");
  const [linked, setLinked] = useState<number | null>(targets[0]?.id ?? null);

  // A linked field is offered only where there is something to point at: a
  // note has no fields, and the entry would lead nowhere.
  const kinds = KINDS.filter((k) => k.kind !== 3 || targets.length > 0);
  const ready = name.trim().length > 0 && (pick !== 3 || linked !== null);
  const add = () =>
    ready && onAdd({ name: name.trim(), value: "", kind: pick, linkedId: pick === 3 ? linked : null });

  return (
    <Modal
      title={t("edit.addCustom")}
      onClose={onClose}
      onSubmit={add}
      footer={
        <>
          <button type="button" className="btn primary" disabled={!ready} onClick={add}>
            {t("item.create")}
          </button>
          <button type="button" className="btn" onClick={onClose}>
            {t("action.cancel")}
          </button>
        </>
      }
    >
      <div className="field">
        <label>{t("edit.kind")}</label>
        <Segmented
          value={String(pick)}
          onChange={(v) => setPick(Number(v))}
          options={kinds.map((k) => ({ id: String(k.kind), label: t(`edit.kind.${k.key}` as Key) }))}
        />
        <span className="hint">
          {t(`edit.kind.${KINDS.find((k) => k.kind === pick)?.key ?? "text"}.hint` as Key)}
        </span>
      </div>
      <div className="field">
        <label>{t("edit.customName")}</label>
        <input value={name} onChange={(e) => setName(e.target.value)} autoFocus spellCheck={false} />
      </div>
      {pick === 3 && (
        <div className="field">
          <label>{t("edit.link")}</label>
          <Picker
            value={linked === null ? "" : String(linked)}
            onChange={(v) => setLinked(v === "" ? null : Number(v))}
            placeholder={t("edit.link.none")}
            options={targets.map((l) => ({ id: String(l.id), label: t(`edit.link.${l.key}` as Key) }))}
          />
        </div>
      )}
    </Modal>
  );
}
