/// Creating an item.
///
/// The core's own kinds are a login, a note, a card and an identity. Kinds a
/// plugin owns join the list while that plugin is on — an ssh key, whose key
/// the ssh plugin makes or reads in its own part of the form.
import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Alert, Modal, Picker, Tabs } from "../ui";
import { t, type Key } from "../i18n";
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
import { kindLabel, type Catalog, type ItemKind } from "../types";

/// The item's kind in the catalogue's terms: the custom-field editor needs it
/// in order to know what a linked field may point at.
const AS_KIND: Record<string, ItemKind> = {
  "1": "login",
  "2": "secure_note",
  "3": "card",
  "4": "identity",
};

const KINDS = [
  { id: "1", key: "login" },
  { id: "2", key: "note" },
  { id: "3", key: "card" },
  { id: "4", key: "identity" },
] as const;

export function NewItem({
  catalog,
  onClose,
  onCreated,
}: {
  catalog: Catalog | null;
  onClose: () => void;
  onCreated: () => void;
}) {
  const [kind, setKind] = useState<string>("1");
  const [name, setName] = useState("");
  const [folder, setFolder] = useState<string | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [notes, setNotes] = useState("");
  const [uris, setUris] = useState<string[]>([""]);
  const [card, setCard] = useState<CardState>(EMPTY_CARD);
  const [who, setWho] = useState<IdentityState>(EMPTY_IDENTITY);
  const [favourite, setFavourite] = useState(false);
  const [reprompt, setReprompt] = useState(false);
  const [custom, setCustom] = useState<Custom[]>([]);
  const [tab, setTab] = useState<"main" | "custom">("main");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const editors = itemEditors(usePlugins());
  const kinds: { id: string; key: string }[] = [
    ...KINDS,
    ...editors.map((e) => ({ id: String(e.code), key: e.kind })),
  ];
  const editor = editors.find((e) => String(e.code) === kind) ?? null;
  const [pluginPatch, setPluginPatch] = useState<Record<string, unknown> | null>(null);
  const [pluginReady, setPluginReady] = useState(true);
  // A plugin's kind is ready only when its part says so; the core's are.
  const kindReady = editor ? pluginReady : true;
  const canCreate = Boolean(name.trim()) && kindReady;

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      await invoke("create_item", {
        kind: Number(kind),
        folderId: folder,
        edit: {
          name,
          username: kind === "1" ? username : null,
          password: kind === "1" ? password : null,
          totp: kind === "1" ? totp : null,
          notes,
          uris: kind === "1" ? uris.map((u) => u.trim()).filter(Boolean) : null,
          card: kind === "3" ? card : null,
          identity: kind === "4" ? who : null,
          favorite: favourite,
          reprompt,
          custom: custom
            .filter((f) => f.name.trim())
            .map((f) => ({
              name: f.name.trim(),
              value: f.value,
              kind: f.kind,
              linked_id: f.kind === 3 ? (f.linkedId ?? null) : null,
            })),
          ...(editor && pluginPatch ? pluginPatch : {}),
        },
      });
      onCreated();
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
      title={t("item.new")}
      onClose={onClose}
      onSubmit={() => canCreate && !busy && void create()}
      footer={
        <>
          {/* The reason in words: a dimmed button says "no" but not "why", and
              a required field may be on another tab. */}
          {!name.trim() ? (
            <span className="hint foot-why">{t("item.needName")}</span>
          ) : (
            !kindReady && <span className="hint foot-why">{t("item.needKindPart")}</span>
          )}
          <button type="button" className="btn primary" disabled={busy || !canCreate} onClick={() => void create()}>
            {busy ? t("action.saving") : t("item.create")}
          </button>
          <button type="button" className="btn" onClick={onClose}>
            {t("action.cancel")}
          </button>
        </>
      }
    >
      {/* The tabs are the body's first block, as in the edit form: otherwise
          the strip of sections obeys the field above it and stands at a
          different height in the two forms. */}
      <Tabs
        value={tab}
        onChange={setTab}
        options={[
          { id: "main", label: t("edit.tab.main") },
          { id: "custom", label: t("edit.tab.custom"), count: custom.length },
        ]}
      />

      {tab === "custom" ? (
        <CustomFields kind={AS_KIND[kind] ?? (editor?.kind as ItemKind | undefined) ?? "login"} fields={custom} onChange={setCustom} />
      ) : (
        <>
          {/* The name takes the full width: it is what an item is searched by
              later. It used to share a row with the folder and was half as
              long as in the edit form. */}
          <div className="field">
            <label>{t("item.name")}</label>
            <input value={name} onChange={(e) => setName(e.target.value)} autoFocus spellCheck={false} />
          </div>

          <div className="pair">
            <div className="field">
              <label>{t("item.kind")}</label>
              <Picker
                value={kind}
                placeholder={t("item.kind")}
                options={kinds.map((k) => ({ id: k.id, label: t(kindLabel(k.key) as Key) }))}
                onChange={(next) => {
                  setKind(next);
                  // Another kind, another part: what the last one answered no
                  // longer applies.
                  setPluginPatch(null);
                  setPluginReady(true);
                }}
              />
            </div>
            <div className="field">
              <label>{t("item.folder")}</label>
              <Picker
                value={folder}
                placeholder={t("item.noFolder")}
                options={(catalog?.folders ?? []).map((f) => ({ id: f.id, label: f.name }))}
                onChange={setFolder}
              />
            </div>
          </div>

      {kind === "1" && (
        <LoginFields
          username={username}
          password={password}
          totp={totp}
          uris={uris}
          onUsername={setUsername}
          onPassword={setPassword}
          onTotp={setTotp}
          onUris={setUris}
          logins={knownLogins(catalog?.items ?? [])}
        />
      )}

      {kind === "3" && <CardFields value={card} onChange={setCard} />}
      {kind === "4" && <IdentityFields value={who} onChange={setWho} logins={knownLogins(catalog?.items ?? [])} />}

        </>
      )}

      {/* The plugin's part stays mounted on both tabs, so that what was chosen
          or pasted survives a look at the custom fields; keyed by the kind, so
          that another kind starts afresh. */}
      {editor && (
        <div hidden={tab !== "main"}>
          <editor.Component
            key={kind}
            detail={null}
            onCopied={() => {}}
            onChange={(patch, ok) => {
              setPluginPatch(patch);
              setPluginReady(ok);
            }}
          />
        </div>
      )}

      {/* After the kind's own part — a plugin's key comes right under the
          name, as in a Bitwarden client — and before what every item has. */}
      {tab === "main" && (
        <>
          <NotesField value={notes} onChange={setNotes} />

          <Behaviour
            favourite={favourite}
            onFavourite={setFavourite}
            reprompt={reprompt}
            onReprompt={setReprompt}
          />
        </>
      )}

      {error && <Alert message={error} />}
    </Modal>
  );
}
