import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Alert, Modal, Picker, Tabs } from "../ui";
import { t } from "../i18n";
import type { Catalog, ItemDetail, PendingEdit } from "../types";
import { usePlugins } from "../plugins/call";
import { itemEditors } from "../plugins";
import {
  Behaviour,
  CardFields,
  CustomFields,
  knownLogins,
  EMPTY_CARD,
  EMPTY_IDENTITY,
  IdentityFields,
  LoginFields,
  NotesField,
  type CardState,
  type Custom,
  type IdentityState,
} from "./ItemFields";
import { invokeSecret } from "../seal";


/// Editing an item. The password and the one-time-code key are pulled in only
/// when the form opens: there is no point holding them in the interface
/// otherwise.
export function EditItem({
  detail,
  onClose,
  onSaved,
  onCopied = () => {},
}: {
  detail: ItemDetail;
  onClose: () => void;
  onSaved: (edit: PendingEdit) => void;
  onCopied?: (text: string) => void;
}) {
  const isLogin = detail.kind === "login";
  // A kind a plugin owns (an ssh key) gets the plugin's part of the form; what
  // it answers is merged into the edit, and it can hold the save back.
  const editor = itemEditors(usePlugins()).find((e) => e.kind === detail.kind) ?? null;
  const [pluginPatch, setPluginPatch] = useState<Record<string, unknown> | null>(null);
  const [pluginReady, setPluginReady] = useState(true);
  const [name, setName] = useState(detail.name);
  const [username, setUsername] = useState("");
  // A secret the item has starts as `null`: kept, and not in the window until
  // a person asks to see or to change it.
  const known = new Set(detail.fields.map((f) => f.key).filter(Boolean));
  const [password, setPassword] = useState<string | null>(isLogin && known.has("password") ? null : "");
  const [totp, setTotp] = useState<string | null>(isLogin && known.has("totp") ? null : "");
  const [notes, setNotes] = useState("");
  const [uris, setUris] = useState<string[]>(detail.uris.length > 0 ? detail.uris : [""]);
  const [custom, setCustom] = useState<Custom[]>(
    detail.custom.map((f) => ({
      name: f.name,
      value: f.hidden ? null : (f.value ?? ""),
      kind: f.kind,
      linkedId: f.linked_id ?? null,
      was: f.name,
    })),
  );
  const [reprompt, setReprompt] = useState(detail.reprompt);
  // The folder used to be set only at creation: an item could not be moved
  // from the edit form, though the server can do it.
  const [folder, setFolder] = useState<string | null>(null);
  const [folders, setFolders] = useState<{ id: string; name: string }[]>([]);
  const [logins, setLogins] = useState<string[]>([]);
  const [favourite, setFavourite] = useState(detail.favorite);
  const [card, setCard] = useState<CardState>(EMPTY_CARD);
  const [who, setWho] = useState<IdentityState>(EMPTY_IDENTITY);
  const isCard = detail.kind === "card";
  const isWho = detail.kind === "identity";
  const [tab, setTab] = useState<"main" | "custom">(
    // The harness needs a link to a tab: ?tab=custom.
    () => (new URLSearchParams(window.location.search).get("tab") === "custom" ? "custom" : "main"),
  );
  const [ready, setReady] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    invoke<Catalog>("vault_items")
      .then((c) => {
        setFolders(c.folders.map((f) => ({ id: f.id, name: f.name })));
        setLogins(knownLogins(c.items));
        setFolder(c.folders.find((f) => f.name === detail.folder_name)?.id ?? null);
      })
      .catch(() => {});
  }, [detail.folder_name]);

  useEffect(() => {
    const load = async () => {
      const get = (field: unknown) =>
        invokeSecret("reveal_secret", { entryId: detail.id, field })
          .then((v) => v ?? "")
          .catch(() => "");
      // By keys rather than by captions: comparing against "Login" broke on a
      // change of the interface's language and on any edit of a translation.
      setUsername(isLogin && known.has("username") ? await get("username") : "");
      setNotes(known.has("note") ? await get("notes") : "");
      setReady(true);
    };
    void load();
  }, [detail, isLogin]);

  // A kept secret, loaded on a press. A failure is an error, never an empty
  // value: saved, an empty value would wipe the real one.
  const revealField = async (field: unknown) => {
    const v = await invokeSecret("reveal_secret", { entryId: detail.id, field });
    if (typeof v !== "string") throw new Error(t("edit.secretNotLoaded"));
    return v;
  };
  const onReveal = async (which: "password" | "totp") => {
    if (which === "password") setPassword(await revealField("password"));
    // The secret, not the code made of it.
    else setTotp(await revealField("totp_secret"));
  };

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      // Only what a person could have changed is sent: "the field was left
      // alone" and "the field was cleared" are different intentions.
      const edit: Record<string, unknown> = { name };
      if (isLogin) {
        edit.username = username;
        // A kept secret is not sent: the item keeps it as it is.
        if (password !== null) edit.password = password;
        if (totp !== null) edit.totp = totp;
      }
      edit.notes = notes;
      if (isLogin) {
        edit.uris = uris.map((u) => u.trim()).filter(Boolean);
      }
      edit.reprompt = reprompt;
      edit.folder_id = folder;
      edit.favorite = favourite;
      if (isCard) edit.card = card;
      if (isWho) edit.identity = who;
      if (pluginPatch) Object.assign(edit, pluginPatch);
      // A renamed field is a new field plus the removal of the old one: in
      // Bitwarden the name is the key.
      // A kept hidden field left as it was is not sent; renamed or of another
      // kind, it is rewritten, and only then is its value fetched.
      const rows = await Promise.all(
        custom
          .filter((f) => f.name.trim())
          .map(async (f) => {
            if (f.value === null) {
              const was = detail.custom.find((o) => o.name === f.was);
              if (was && f.was === f.name.trim() && was.kind === f.kind) return null;
            }
            const value = f.value ?? (await revealField({ custom: f.was }));
            return { name: f.name.trim(), value, kind: f.kind, linked_id: f.kind === 3 ? (f.linkedId ?? null) : null };
          }),
      );
      edit.custom = rows.filter(Boolean);
      edit.remove_custom = [
        ...detail.custom.map((f) => f.name).filter((was) => !custom.some((f) => f.was === was)),
        ...custom.filter((f) => f.was && f.was !== f.name.trim()).map((f) => f.was),
      ];
      onSaved(await invoke<PendingEdit>("update_item", { entryId: detail.id, edit }));
      onClose();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };


  return (
    <Modal
      wide
      title={t("edit.title")}
      onClose={onClose}
      onSubmit={() => ready && pluginReady && !busy && void save()}
      footer={
        <>
          <button type="button" className="btn primary" disabled={busy || !ready || !pluginReady} onClick={() => void save()}>
            {busy ? t("action.saving") : t("action.save")}
          </button>
          <button type="button" className="btn" onClick={onClose}>
            {t("action.cancel")}
          </button>
        </>
      }
    >
      {/* Two tabs instead of one long sheet: custom fields are needed rarely
          and take more room than everything else. */}
      <Tabs
        value={tab}
        onChange={setTab}
        options={[
          { id: "main", label: t("edit.tab.main") },
          { id: "custom", label: t("edit.tab.custom"), count: custom.length },
        ]}
      />

      {tab === "main" ? (
        <>
          <div className="field">
            <label>{t("edit.name")}</label>
            <input value={name} onChange={(e) => setName(e.target.value)} autoFocus />
          </div>

          <div className="field">
            <label>{t("item.folder")}</label>
            <Picker
              value={folder}
              placeholder={t("item.noFolder")}
              options={folders.map((f) => ({ id: f.id, label: f.name }))}
              onChange={setFolder}
            />
          </div>

          {isLogin && (
            <LoginFields
              username={username}
              password={password}
              totp={totp}
              uris={uris}
              onUsername={setUsername}
              onPassword={setPassword}
              onTotp={setTotp}
              onUris={setUris}
              onReveal={onReveal}
              logins={logins}
            />
          )}

          {isCard && <CardFields value={card} onChange={setCard} />}
          {isWho && <IdentityFields value={who} onChange={setWho} logins={logins} />}

          <NotesField value={notes} onChange={setNotes} />

          <Behaviour
            favourite={favourite}
            onFavourite={setFavourite}
            reprompt={reprompt}
            onReprompt={setReprompt}
          />
        </>
      ) : (
        <CustomFields kind={detail.kind} fields={custom} onChange={setCustom} reveal={(was) => revealField({ custom: was })} />
      )}

      {/* Mounted on both tabs and hidden on the second: a chosen replacement
          of the key must survive a look at the custom fields. Last in the
          form, since its danger zone belongs at the bottom. */}
      {editor && (
        <div hidden={tab !== "main"}>
          <editor.Component
            detail={detail}
            onCopied={onCopied}
            onChange={(patch, ok) => {
              setPluginPatch(patch);
              setPluginReady(ok);
            }}
          />
        </div>
      )}

      {error && <Alert message={error} />}

    </Modal>
  );
}
