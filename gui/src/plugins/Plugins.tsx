import { useCallback, useEffect, useState } from "react";
import { Alert, Disclosure, Empty, Icon, Modal, Row, Rows, Section, Segmented, Toggle } from "../ui";
import { t, tMaybe } from "../i18n";
import type { Key } from "../i18n";
import {
  catalog,
  enablePlugin,
  installEntry,
  installPlugin,
  pickPluginPackage,
  pluginTitle,
  removePlugin,
  sources,
  trustPublisher,
  usePlugins,
} from "./call";
import {
  fingerprintPhrase,
  sortPermissions,
  validSource,
  type CatalogEntry,
  type Manifest,
  type Permission,
} from "./types";

/// A permission's caption for a person. Exactly the words `Permission::label()`
/// has on the daemon's side, but they live here: the interface has the person's
/// language and the daemon does not.
const PERMISSION_KEY: Record<Permission, Key> = {
  entries: "plugin.perm.entries",
  items: "plugin.perm.items",
  items_write: "plugin.perm.itemsWrite",
  secrets: "plugin.perm.secrets",
  notices: "plugin.perm.notices",
  ssh_sign: "plugin.perm.sshSign",
  network: "plugin.perm.network",
  keychain: "plugin.perm.keychain",
};

/// A permission the interface does not know is shown by its own name: a
/// request must not be hidden without a word — it is what the decision is made
/// on.
function permissionLabel(permission: Permission): string {
  const key = PERMISSION_KEY[permission] as Key | undefined;
  return key ? t(key) : permission;
}

/// The dangerous permissions are marked out in colour: "read passwords" and
/// "go to the network" together are the chance to carry secrets away, and in
/// one grey list that would look no different from "show notices".
function permissionTone(permission: Permission): string {
  return permission === "secrets" || permission === "network" ? " hot" : "";
}

function Permissions({ permissions }: { permissions: Permission[] }) {
  if (permissions.length === 0) return <p className="hint">{t("plugin.perm.none")}</p>;
  return (
    <ul className="perm-list">
      {sortPermissions(permissions).map((p) => (
        <li key={p} className={`perm${permissionTone(p)}`}>
          <Icon name="check" size={12} />
          <span>{permissionLabel(p)}</span>
        </li>
      ))}
    </ul>
  );
}

/// A package's size in human words: bytes in the catalogue, and "12 KB" on the
/// card. Precision is not wanted here, the order of magnitude is.
function humanSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "";
  if (bytes < 1024) return t("unit.bytes", { n: bytes });
  if (bytes < 1024 * 1024) return t("unit.kb", { n: Math.round(bytes / 1024) });
  const mb = bytes / (1024 * 1024);
  return t("unit.mb", { n: mb >= 10 ? Math.round(mb) : Math.round(mb * 10) / 10 });
}

type Dialog =
  /// A freshly installed plugin: it is already on disk but switched off, and
  /// this is its only conversation with a person about permissions. `from` is
  /// where the package came from: for an unsigned one that is the only measure
  /// of trust there is.
  | { kind: "consent"; manifest: Manifest; from?: string }
  /// A publisher's key to confirm: the five words of the fingerprint and a
  /// "yes" of its own.
  | { kind: "trust"; entry: CatalogEntry }
  | { kind: "remove"; manifest: Manifest };

/// The "Plugins" section of the settings: the catalogue first — what there is
/// to install — then what is already installed, and only at the end installing
/// from disk.
export function PluginsSettings() {
  // The catalogue is part of the plugins section rather than a section next to
  // it: installing and looking at what is installed happen in one place,
  // through a switch.
  const [part, setPart] = useState<"catalog" | "installed">("catalog");
  const plugins = usePlugins();
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  /// `null` means the catalogue has not been asked yet. That is not the same
  /// as an empty catalogue: emptiness is explained in words, not knowing by a
  /// line of waiting.
  const [entries, setEntries] = useState<CatalogEntry[] | null>(null);
  const [reading, setReading] = useState(false);

  const run = async (what: string, fn: () => Promise<unknown>) => {
    setBusy(what);
    setError(null);
    try {
      await fn();
      return true;
    } catch (e) {
      setError(String(e));
      return false;
    } finally {
      setBusy(null);
    }
  };

  /// A catalogue out of reach is not an error across the whole screen: the
  /// daemon gives out its cache marked `stale`, and one quiet line speaks of
  /// it. An exception means the daemon itself did not answer — that is what
  /// has to be said.
  const readCatalog = useCallback(async (refresh: boolean) => {
    setReading(true);
    try {
      setEntries(await catalog(refresh));
      setError(null);
    } catch (e) {
      setError(String(e));
      setEntries((cur) => cur ?? []);
    } finally {
      setReading(false);
    }
  }, []);

  useEffect(() => {
    void readCatalog(false);
  }, [readCatalog]);

  const install = async (archive: boolean) => {
    setError(null);
    const path = await pickPluginPackage(archive).catch((e: unknown) => {
      setError(String(e));
      return null;
    });
    if (!path) return;
    await run("install", async () => {
      const manifest = await installPlugin(path);
      setDialog({ kind: "consent", manifest, from: path });
      await readCatalog(false);
    });
  };

  const stale = entries?.some((e) => e.stale) ?? false;

  return (
    <>
      {/* Installing from disk comes first: a developer's path, but a short
          one, and there is no point hiding it under the catalogue's list. */}
      {/* ── Installing from disk ─────────────────────────────────────
          A developer's path, so it is the last block and has no main action:
          the section's main action is the button in the catalogue. */}
      <Section title={t("settings.plugins.install")} tone="mint">
        <Rows>
          <Row title={t("settings.plugins.installTitle")} hint={t("settings.plugins.installHint")}>
            {/* Two ways in rather than one: the system's directory picker and
                its file picker are different windows, and which to open is
                decided by the button that was pressed, not by a guess. */}
            <div className="row-actions">
              <button type="button" className="btn" disabled={busy !== null} onClick={() => void install(true)}>
                {t("settings.plugins.pickArchive")}
              </button>
              <button type="button" className="btn" disabled={busy !== null} onClick={() => void install(false)}>
                {busy === "install" ? t("settings.plugins.installing") : t("settings.plugins.pickFolder")}
              </button>
            </div>
          </Row>
          <ByUrlRow
            busy={busy === "url"}
            disabled={busy !== null}
            onInstall={(url) =>
              void run("url", async () => {
                const manifest = await installPlugin(url);
                setDialog({ kind: "consent", manifest, from: url });
                await readCatalog(false);
              })
            }
          />
        </Rows>
      </Section>

      <Segmented<"catalog" | "installed">
        value={part}
        onChange={setPart}
        options={[
          { id: "catalog", label: t("settings.tab.catalog"), count: entries?.length },
          { id: "installed", label: t("settings.plugins.installedTitle"), count: plugins.length },
        ]}
      />

      {part === "catalog" && (
      <>
      {/* ── The catalogue ────────────────────────────────────────────
          First: the ordinary path is to choose from what is ready rather
          than to hunt for a package in the file system. */}
      <header className="plugins-head">
        <h3>{t("settings.plugins.catalog")}</h3>
        <p className="hint">{t("settings.plugins.catalogHint")}</p>
        <button type="button" className="btn quiet" disabled={reading} onClick={() => void readCatalog(true)}>
          <Icon name="sync" size={13} />
          <span>{reading ? t("settings.plugins.refreshing") : t("settings.plugins.refresh")}</span>
        </button>
      </header>

      {/* A list from the cache gets a quiet line rather than a red band: the
          installed plugins do not suffer from a catalogue out of reach. */}
      {stale && (
        <p className="catalog-stale">
          <Icon name="clock" size={13} />
          <span>{t("settings.plugins.stale")}</span>
          <button type="button" className="btn quiet" disabled={reading} onClick={() => void readCatalog(true)}>
            {t("settings.plugins.refresh")}
          </button>
        </p>
      )}

      {entries === null && <p className="hint">{t("settings.plugins.reading")}</p>}

      {entries?.length === 0 && (
        <Empty
          icon="globe"
          title={t("settings.plugins.empty.title")}
          body={t("settings.plugins.empty.body")}
          action={
            <button type="button" className="btn" disabled={reading} onClick={() => void readCatalog(true)}>
              {reading ? t("settings.plugins.refreshing") : t("settings.plugins.refresh")}
            </button>
          }
        />
      )}

      {entries?.map((e) => (
        <CatalogCard
          key={`${e.source}/${e.id}`}
          entry={e}
          busy={busy === `catalog:${e.id}`}
          disabled={busy !== null}
          onInstall={() =>
            void run(`catalog:${e.id}`, async () => {
              const manifest = await installEntry(e);
              setDialog({ kind: "consent", manifest, from: e.source });
              await readCatalog(false);
            })
          }
          onTrust={() => setDialog({ kind: "trust", entry: e })}
        />
      ))}

      <SourcesBox onChanged={() => void readCatalog(true)} />

      </>
      )}

      {part === "installed" && (
      <>
      {/* ── Installed ────────────────────────────────────────────────
          The second part, with a heading of its own: the cards below are
          about what already lies on disk, not about what is on offer. */}
      <header className="plugins-head">
        <h3>{t("settings.plugins.installedTitle")}</h3>
        <p className="hint">{t("settings.plugins.installedHint")}</p>
      </header>

      {plugins.map((m) => (
        <PluginCard
          key={m.id}
          manifest={m}
          /* A withdrawal is announced by the catalogue rather than by the
             manifest on disk: the reason is taken from the entry when the
             daemon did not put it into the manifest itself. */
          revoked={m.revoked_reason ?? entries?.find((e) => e.id === m.id && e.revoked)?.reason}
          busy={busy === m.id}
          onToggle={(on) => void run(m.id, () => enablePlugin(m.id, on))}
          onRemove={() => setDialog({ kind: "remove", manifest: m })}
        />
      ))}


      </>
      )}

      {/* The dialogues and the error are shared by both pages: trust in a
          publisher is asked from the catalogue, and removing a plugin from the
          list of installed ones. */}
      {error && <Alert message={error} onClose={() => setError(null)} />}
      {dialog?.kind === "trust" && (
        <TrustModal
          entry={dialog.entry}
          busy={busy === `trust:${dialog.entry.publisher ?? ""}`}
          onClose={() => setDialog(null)}
          onTrust={() => {
            void run(`trust:${dialog.entry.publisher ?? ""}`, async () => {
              await trustPublisher(dialog.entry.publisher ?? "");
              await readCatalog(false);
            }).then((ok) => ok && setDialog(null));
          }}
        />
      )}

      {dialog?.kind === "consent" && (
        <ConsentModal
          manifest={dialog.manifest}
          from={dialog.from}
          onClose={() => setDialog(null)}
          onAgree={async () => {
            const ok = await run(dialog.manifest.id, () => enablePlugin(dialog.manifest.id, true));
            if (ok) setDialog(null);
          }}
        />
      )}

      {dialog?.kind === "remove" && (
        <Modal
          title={t("settings.plugins.remove.title", { name: pluginTitle(dialog.manifest) })}
          onClose={() => setDialog(null)}
          footer={
            <button
              type="button"
              className="btn danger"
              disabled={busy !== null}
              onClick={() => {
                void run(dialog.manifest.id, () => removePlugin(dialog.manifest.id)).then(async (ok) => {
                  if (!ok) return;
                  setDialog(null);
                  await readCatalog(false);
                });
              }}
            >
              {busy ? t("action.saving") : t("settings.plugins.remove.action")}
            </button>
          }
        >
          <p className="hint">{t("settings.plugins.remove.body", { name: pluginTitle(dialog.manifest) })}</p>
        </Modal>
      )}
    </>
  );
}

/// A catalogue card: an icon, a name, a version, a size, a description and one
/// action on the right. The permissions are a short line here; the full list is
/// seen in the consent dialogue, when the decision is being made.
function CatalogCard({
  entry,
  busy,
  disabled,
  onInstall,
  onTrust,
}: {
  entry: CatalogEntry;
  busy: boolean;
  disabled: boolean;
  onInstall: () => void;
  onTrust: () => void;
}) {
  const size = humanSize(entry.size);
  // A publisher outside the list of trusted ones is not "a fault of the
  // catalogue" but an unfinished conversation: the key is confirmed first, and
  // only then does "Install" appear.
  const untrusted = entry.trusted === false;
  return (
    <section className={`block catalog-card${entry.revoked ? " revoked" : ""}`}>
      <div className="plugin-head">
        <Icon name={entry.icon || "note"} size={16} />
        <div className="plugin-name">
          <h3>{entry.title || entry.id}</h3>
          {/* The publisher gets a quiet line under the name: for a signed
              package from a trusted publisher this is the ordinary state of
              things, and there is nothing to make a noise about. */}
          {entry.publisher && (
            <p className="catalog-publisher">
              {t("settings.plugins.publisher", { name: entry.publisher })}
              {entry.signed === false && <span className="chip warn">{t("settings.plugins.unsigned")}</span>}
              {untrusted && <span className="chip bad">{t("settings.plugins.untrusted")}</span>}
            </p>
          )}
          <div className="plugin-marks">
            {entry.version && <span className="mono">{entry.version}</span>}
            {size && <span className="hint">{size}</span>}
            {entry.update && (
              <span className="chip warn">
                {t("settings.plugins.updateFrom", { from: entry.installed_version || "—", to: entry.version })}
              </span>
            )}
            {entry.installed && !entry.update && !entry.revoked && (
              <span className="chip ok">{t("settings.plugins.installedMark")}</span>
            )}
          </div>
        </div>

        {/* One action to a card: trust the publisher, install, update — or a
            quiet "installed" mark that promises nothing to press. A withdrawn
            version has no action at all. */}
        {entry.revoked ? null : untrusted ? (
          <button type="button" className="btn" disabled={disabled} onClick={onTrust}>
            {t("settings.plugins.trust.action")}
          </button>
        ) : entry.installed && !entry.update ? (
          <span className="catalog-done">
            <Icon name="check" size={13} />
            <span>{t("settings.plugins.installedMark")}</span>
          </span>
        ) : (
          <button type="button" className="btn primary" disabled={disabled} onClick={onInstall}>
            {busy
              ? t("settings.plugins.installing")
              : entry.update
                ? t("settings.plugins.upgrade")
                : t("settings.plugins.get")}
          </button>
        )}
      </div>

      {/* A withdrawn version: the reason in plain sight, nothing to install. */}
      {entry.revoked && (
        <p className="catalog-revoked">
          <Icon name="warn" size={13} />
          <span>{t("settings.plugins.revoked", { reason: entry.reason || t("settings.plugins.revokedNoReason") })}</span>
        </p>
      )}

      {/* While the publisher is not trusted there is nothing to install — that
          is said in words rather than by one grey button. */}
      {untrusted && !entry.revoked && <p className="hint warn">{t("settings.plugins.untrustedHint")}</p>}

      {entry.description && <p className="plugin-about">{tMaybe(entry.description, entry.description)}</p>}

      <div className="catalog-foot">
        <span className="hint">{t("settings.plugins.from", { source: sourceHost(entry.source) })}</span>
        <ul className="perm-chips">
          {sortPermissions(entry.permissions ?? []).map((p) => (
            <li key={p} className={`chip${permissionTone(p) ? " bad" : ""}`}>
              {permissionLabel(p)}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

/// Where an entry comes from: a card needs not the catalogue's whole address
/// but a recognisable name. A `file://` one is shown by the last stretch of its
/// path — that is how a local build of one's own is recognised.
function sourceHost(source: string): string {
  if (!source) return "—";
  try {
    const url = new URL(source);
    return url.protocol === "file:" ? url.pathname.split("/").filter(Boolean).slice(-2).join("/") : url.host;
  } catch {
    return source;
  }
}

/// The catalogues' addresses. Below the catalogue and folded away: an ordinary
/// person never needs the list of sources once, and somebody keeping a
/// catalogue of their own needs it every day.
function SourcesBox({ onChanged }: { onChanged: () => void }) {
  const [list, setList] = useState<string[] | null>(null);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [bad, setBad] = useState<string | null>(null);

  useEffect(() => {
    void sources()
      .then(setList)
      .catch(() => setList([]));
  }, []);

  const save = async (next: string[]) => {
    setBusy(true);
    setBad(null);
    try {
      setList(await sources(next));
      onChanged();
    } catch (e) {
      setBad(String(e));
    } finally {
      setBusy(false);
    }
  };

  const add = () => {
    const url = draft.trim();
    if (!url) return;
    // The scheme is checked before going to the daemon: it is more honest to
    // speak of a typo in an address at once than to answer "the source was
    // refused".
    if (!validSource(url)) {
      setBad(t("settings.plugins.sourceBad"));
      return;
    }
    if (list?.includes(url)) {
      setBad(t("settings.plugins.sourceDupe"));
      return;
    }
    setDraft("");
    void save([...(list ?? []), url]);
  };

  return (
    <Disclosure title={t("settings.plugins.sources", { n: list?.length ?? 0 })}>
      <p className="hint">{t("settings.plugins.sourcesHint")}</p>

      <ul className="source-list">
        {(list ?? []).map((s) => (
          <li key={s}>
            <span className="mono">{s}</span>
            <button
              type="button"
              className="btn quiet icon-only"
              title={t("settings.plugins.sourceRemove")}
              aria-label={t("settings.plugins.sourceRemove")}
              disabled={busy}
              onClick={() => void save((list ?? []).filter((one) => one !== s))}
            >
              <Icon name="trash" size={13} />
            </button>
          </li>
        ))}
        {list?.length === 0 && <li className="hint">{t("settings.plugins.sourcesNone")}</li>}
      </ul>

      <div className="source-add">
        <input
          value={draft}
          onChange={(e) => {
            setDraft(e.target.value);
            setBad(null);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") add();
          }}
          className="mono"
          placeholder={t("settings.plugins.sourcePlaceholder")}
          aria-label={t("settings.plugins.sourceAdd")}
          spellCheck={false}
          autoCapitalize="off"
        />
        <button type="button" className="btn" disabled={busy || draft.trim() === ""} onClick={add}>
          {t("settings.plugins.sourceAdd")}
        </button>
      </div>

      {bad && <p className="hint bad">{bad}</p>}
    </Disclosure>
  );
}

/// Installing by a package's address — for somebody who was given a link past
/// the catalogue. There is nothing to check such a package's fingerprint
/// against, and the consent dialogue will say so; one line of warning is enough
/// here.
function ByUrlRow({
  busy,
  disabled,
  onInstall,
}: {
  busy: boolean;
  disabled: boolean;
  onInstall: (url: string) => void;
}) {
  const [url, setUrl] = useState("");
  const ready = url.trim().startsWith("https://");
  return (
    <Row title={t("settings.plugins.byUrl")} hint={t("settings.plugins.byUrlHint")}>
      <div className="row-actions">
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="mono url-input"
          placeholder={t("settings.plugins.byUrlPlaceholder")}
          aria-label={t("settings.plugins.byUrl")}
          spellCheck={false}
          autoCapitalize="off"
        />
        <button
          type="button"
          className="btn"
          disabled={disabled || !ready}
          onClick={() => {
            onInstall(url.trim());
            setUrl("");
          }}
        >
          {busy ? t("settings.plugins.installing") : t("settings.plugins.get")}
        </button>
      </div>
    </Row>
  );
}

/// A plugin's card: an icon, a name, a version, an origin, a description, a
/// switch and the list of what it asks for.
function PluginCard({
  manifest,
  revoked,
  busy,
  onToggle,
  onRemove,
}: {
  manifest: Manifest;
  /// The reason for a withdrawal, when the catalogue has withdrawn the version
  /// that is installed. The daemon switches it off itself — the card is left to
  /// explain what happened.
  revoked?: string;
  busy: boolean;
  onToggle: (on: boolean) => void;
  onRemove: () => void;
}) {
  const external = manifest.origin === "external";
  return (
    <section className={`block plugin-card${manifest.enabled ? "" : " off"}${revoked ? " revoked" : ""}`}>
      <div className="plugin-head">
        <Icon name={manifest.icon || "note"} size={16} />
        <div className="plugin-name">
          <h3>{pluginTitle(manifest)}</h3>
          <div className="plugin-marks">
            {manifest.version && <span className="mono">{manifest.version}</span>}
            <span className={`chip ${external ? "on" : "ok"}`}>
              {t(external ? "plugin.origin.external" : "plugin.origin.builtin")}
            </span>
            {!manifest.enabled && <span className="chip warn">{t("plugin.state.off")}</span>}
            {revoked && <span className="chip bad">{t("settings.plugins.revokedMark")}</span>}
          </div>
        </div>
        <Toggle on={manifest.enabled} onChange={onToggle} />
      </div>

      {/* The version has been withdrawn by the catalogue: the reason in the
          same line as in the catalogue — the same thing is read in both
          lists. */}
      {revoked && (
        <p className="catalog-revoked">
          <Icon name="warn" size={13} />
          <span>{t("settings.plugins.revokedInstalled", { reason: revoked })}</span>
        </p>
      )}

      {manifest.description && <p className="plugin-about">{tMaybe(manifest.description, manifest.description)}</p>}

      {/* A switched-off one lies on disk waiting for consent — that is said in
          words rather than by one grey tone of the card. */}
      {!manifest.enabled && <p className="hint warn">{t("plugin.state.offHint")}</p>}

      <div className="plugin-perms">
        <h4>{t("plugin.perm.title")}</h4>
        <Permissions permissions={manifest.permissions ?? []} />
      </div>

      {/* Only an external one can be deleted: a built-in one is compiled
          together with the daemon and there is nothing to remove it with —
          only to switch it off. The destructive action lives on a line of its
          own at the bottom of the card rather than beside the switch. */}
      {external && (
        <div className="plugin-danger">
          <span className="text">
            <b>{t("settings.plugins.remove")}</b>
            <span className="hint">{t("settings.plugins.removeHint")}</span>
          </span>
          <button type="button" className="btn danger" disabled={busy} onClick={onRemove}>
            {t("settings.plugins.remove.action")}
          </button>
        </div>
      )}
    </section>
  );
}

/// Consent to the permissions. The plugin already lies on disk and is already
/// switched off: the main action here is to switch it on, and closing the
/// window means "let it lie there switched off" rather than "cancel the
/// installation".
function ConsentModal({
  manifest,
  from,
  onClose,
  onAgree,
}: {
  manifest: Manifest;
  /// Where the package came from: a catalogue's address, a link or a path on
  /// disk.
  from?: string;
  onClose: () => void;
  onAgree: () => void;
}) {
  const name = pluginTitle(manifest);
  const added = manifest.added_permissions ?? [];
  return (
    <Modal
      title={t("settings.plugins.consent.title", { name })}
      onClose={onClose}
      footer={
        <button type="button" className="btn primary" onClick={onAgree}>
          {t("settings.plugins.consent.action")}
        </button>
      }
    >
      <p className="hint">{t("settings.plugins.consent.body", { name, version: manifest.version || "—" })}</p>
      {manifest.description && <p className="plugin-about">{tMaybe(manifest.description, manifest.description)}</p>}

      {/* A package with no signature — a directory from disk, an archive or an
          address typed in by hand. That is said at full voice and on a par with
          the permissions rather than as a footnote at the bottom: where a
          package came from is half the decision. */}
      {manifest.unverified && (
        <div className="consent-warn">
          <h4>
            <Icon name="warn" size={13} />
            <span>{t("settings.plugins.consent.unverified")}</span>
          </h4>
          <p>{t("settings.plugins.consent.unverifiedBody")}</p>
          {from && (
            <p className="where">
              <span className="k">{t("settings.plugins.consent.from")}</span>
              <span className="mono">{from}</span>
            </p>
          )}
        </div>
      )}

      {/* The update asked for more than before: it is the addition that is
          shown. The same list in full was already seen at the installation, and
          a second time it is read by the eyes rather than by the head. */}
      {added.length > 0 && (
        <div className="plugin-perms added">
          <h4>{t("plugin.perm.added")}</h4>
          <Permissions permissions={added} />
          <p className="hint">{t("settings.plugins.consent.addedBody")}</p>
        </div>
      )}

      <div className="plugin-perms">
        <h4>{added.length > 0 ? t("plugin.perm.all") : t("plugin.perm.title")}</h4>
        <Permissions permissions={manifest.permissions ?? []} />
      </div>
      <p className="hint">{t("settings.plugins.consent.later")}</p>
    </Modal>
  );
}

/// Trust in a publisher: a conversation of its own, a "yes" of its own.
///
/// The five words of the fingerprint are the only thing a person is able to
/// check against what they were told aloud or shown on a site. Sixty-four
/// hexadecimal characters they will not check, which is why they are not
/// here.
function TrustModal({
  entry,
  busy,
  onClose,
  onTrust,
}: {
  entry: CatalogEntry;
  busy: boolean;
  onClose: () => void;
  onTrust: () => void;
}) {
  const publisher = entry.publisher ?? "—";
  return (
    <Modal
      title={t("settings.plugins.trust.title", { name: publisher })}
      onClose={onClose}
      footer={
        <button type="button" className="btn primary" disabled={busy} onClick={onTrust}>
          {busy ? t("action.saving") : t("settings.plugins.trust.confirm")}
        </button>
      }
    >
      <p className="hint">{t("settings.plugins.trust.body", { name: publisher, plugin: entry.title || entry.id })}</p>

      <div className="kv">
        <span className="k">{t("settings.plugins.trust.publisher")}</span>
        <span className="v mono">{publisher}</span>
      </div>
      <div className="kv">
        <span className="k">{t("settings.plugins.trust.source")}</span>
        <span className="v mono">{entry.source}</span>
      </div>

      <div className="fingerprint big">
        <span className="mono">{fingerprintPhrase(entry.fingerprint) || "—"}</span>
      </div>
      <p className="hint">{t("settings.plugins.trust.fingerprintHint")}</p>
    </Modal>
  );
}
