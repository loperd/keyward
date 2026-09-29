/// Search as an overlay over the window.
///
/// Not a field in a corner but something called from anywhere with Cmd+K:
/// searching happens more often than anything else, and the way to the search
/// has to be shorter than the way to the mouse.
import { useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Icon, Monogram, useEscape } from "./ui";
import { domainOf, useSiteIcon } from "./icons";
import { t } from "./i18n";
import type { Key } from "./i18n";
import { kindKey, kindLabel, type Catalog, type ItemDetail, type VaultItem } from "./types";

/// What was in the foreground when the hotkey was pressed.
export type FillField = { kind: "password" | "username" | "totp" | "card" | "text" | "unknown"; role: string; label: string; cells?: number; login?: { label: string; named: boolean } | null };
export type FillContext = { app: string; bundle_id: string; pid: number; url: string | null; domain: string | null; field: FillField | null; window?: string | null };

/// What to type by default when the field under the cursor is recognised.
/// A card field takes only a card: out of a login there is nothing to put
/// into it, and the choice is shown instead.
function modeForField(f: FillField | null | undefined, item?: VaultItem): FillMode | null {
  if (!f) return null;
  if (f.kind === "card") return item?.kind === "card" ? { kind: "card" } : null;
  if (f.kind === "password") return { kind: "password" };
  if (f.kind === "totp") return { kind: "totp" };
  // Both values only into a proven login form; a lone login field takes the
  // login alone.
  if (f.kind === "username") return f.login ? { kind: "both" } : { kind: "username" };
  return null;
}
export type FillMode = { kind: "both" } | { kind: "username" } | { kind: "password" } | { kind: "totp" } | { kind: "card" } | { kind: "custom"; name: string };
type FillOption = { mode: FillMode; label: string; hint: string; icon: string; hot?: string };

/// A search tag: `site:dash.cloudflare.com`, `name:gitlab`. A chip inside the
/// line.
type TagType = "site" | "name" | "type" | "folder" | "org";
type Tag = { type: TagType; value: string };
const TAG_TYPES: TagType[] = ["site", "name", "type", "folder", "org"];
const TAG_RE = /^(site|name|type|folder|org|organization):(.*)$/i;
const KIND_KEYS = ["login", "card", "identity", "note", "ssh_key"] as const;
const TAG_ICON: Record<TagType, string> = { site: "all", name: "note", type: "card", folder: "folder", org: "identity" };

function normalizeTagType(raw: string): TagType {
  const t = raw.toLowerCase();
  return t === "organization" ? "org" : (t as TagType);
}

/// The second-level suffixes whose "base domain" is three labels rather than
/// two: otherwise `co.uk` would count as one site for the whole of Britain.
const TWO_LEVEL = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz",
  "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "co.kr", "or.kr", "com.cn", "net.cn", "org.cn",
  "com.hk", "com.sg", "com.tw", "co.in", "net.in", "org.in", "co.id", "co.il", "co.th",
  "com.br", "net.br", "org.br", "com.mx", "com.ar", "com.co", "com.pe", "com.ve", "com.tr",
  "co.za", "com.ua", "net.ua", "org.ua", "kiev.ua", "com.pl", "net.pl", "org.pl", "com.ru", "spb.ru", "msk.ru",
]);

/// The base domain as Bitwarden understands it for a "base domain" match:
/// `auth.openvpn.com` and `paycore.openvpn.com` are one site,
/// `openvpn.com`.
export function baseDomain(host: string): string {
  const parts = host.toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  const tail2 = parts.slice(-2).join(".");
  return TWO_LEVEL.has(tail2) ? parts.slice(-3).join(".") : tail2;
}

function siteMatches(item: VaultItem, d: string): boolean {
  const want = d.toLowerCase();
  const wantBase = baseDomain(want);
  return item.uris.some((u) => {
    const h = domainOf(u);
    return h !== null && (h === want || h.endsWith("." + want) || want.endsWith("." + h) || baseDomain(h) === wantBase);
  });
}

function passesTags(item: VaultItem, tags: Tag[]): boolean {
  return tags.every((tg) => {
    const v = tg.value.toLowerCase();
    switch (tg.type) {
      case "site":
        return siteMatches(item, tg.value);
      case "name":
        return item.name.toLowerCase().includes(v);
      case "type":
        return kindKey(item.kind) === v || t(kindLabel(kindKey(item.kind)) as Key).toLowerCase() === v;
      case "folder":
        return (item.folder_name ?? "").toLowerCase() === v;
      case "org":
        return (item.org_name ?? "").toLowerCase() === v;
    }
  });
}

/// How many rows are shown. Nobody reads more than twenty anyway, and the
/// search stops being instant.
const LIMIT = 20;

export function Spotlight({
  catalog,
  serverUrl,
  onPick,
  onClose,
  fill = null,
  onFill,
}: {
  catalog: Catalog | null;
  serverUrl: string;
  onPick: (id: string) => void;
  onClose: () => void;
  /// The autofill mode: where we came from and where to type.
  fill?: FillContext | null;
  onFill?: (id: string, mode: FillMode) => void;
}) {
  const [query, setQuery] = useState("");
  const [recent, setRecent] = useState<string[]>([]);
  const [trusted, setTrusted] = useState<boolean | null>(null);
  // The tag chips. In fill mode the tab's site becomes a chip at once: it is
  // visible, and it can be taken off with Backspace to search the whole
  // vault.
  const [tags, setTags] = useState<Tag[]>(() => (fill?.domain ? [{ type: "site", value: fill.domain }] : []));
  const [sugCursor, setSugCursor] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  // What is being typed just now: a tag with a colon, or ordinary text.
  const typing = TAG_RE.exec(query.trim());
  const typingType = typing ? normalizeTagType(typing[1]) : null;
  const typingValue = typing ? typing[2].trim().toLowerCase() : "";

  // Value hints for the tag being typed: the items' domains or their names.
  const suggestions = useMemo(() => {
    if (!catalog || !typingType) return [] as string[];
    const pool = catalog.items.filter((i) => !i.deleted && passesTags(i, tags));
    const values = new Set<string>();
    if (typingType === "site") {
      for (const i of pool) for (const u of i.uris) {
        const h = domainOf(u);
        if (h) values.add(h);
      }
    } else if (typingType === "name") {
      for (const i of pool) values.add(i.name);
    } else if (typingType === "type") {
      for (const k of KIND_KEYS) if (pool.some((i) => kindKey(i.kind) === k)) values.add(k);
    } else if (typingType === "folder") {
      for (const i of pool) if (i.folder_name) values.add(i.folder_name);
    } else {
      for (const i of pool) if (i.org_name) values.add(i.org_name);
    }
    return [...values]
      .filter((v) => v.toLowerCase().includes(typingValue))
      .sort((a, b) => Number(!a.toLowerCase().startsWith(typingValue)) - Number(!b.toLowerCase().startsWith(typingValue)) || a.localeCompare(b))
      .slice(0, 8);
  }, [catalog, typingType, typingValue, tags]);

  // A hint of the kinds when the line is empty and somebody has only just
  // started: "site:", "name:".
  const typeHints = !typing && query.trim() !== "" && TAG_TYPES.some((tt) => tt.startsWith(query.trim().toLowerCase())) && !query.includes(" ")
    ? TAG_TYPES.filter((tt) => tt.startsWith(query.trim().toLowerCase()))
    : [];

  const addTag = (type: TagType, value: string) => {
    const v = value.trim();
    if (!v) return;
    setTags((cur) => [...cur.filter((tg) => !(tg.type === type && tg.value === v)), { type, value: v }]);
    setQuery("");
    setSugCursor(0);
    inputRef.current?.focus();
  };

  const popTag = () => {
    setTags((cur) => {
      const last = cur[cur.length - 1];
      if (last) setQuery(`${last.type}:${last.value}`);
      return cur.slice(0, -1);
    });
  };

  useEffect(() => setSugCursor(0), [typingType, typingValue]);
  // The second step of filling: the chosen item, and what of it to type.
  const [picked, setPicked] = useState<VaultItem | null>(null);
  const [options, setOptions] = useState<FillOption[]>([]);
  const [optCursor, setOptCursor] = useState(0);

  useEffect(() => {
    if (!fill) return;
    let alive = true;
    const check = () =>
      invoke<boolean>("autofill_trusted")
        .then((ok) => {
          if (alive) setTrusted(ok);
          return ok;
        })
        .catch(() => false);
    void check().then((ok) => {
      // With no permission the system's dialogue is called at once: the same
      // call adds the application to the list. After that we poll every second
      // — the switch is flicked in the settings, and the warning has to go out
      // by itself.
      if (!ok) void invoke<boolean>("autofill_request_access").catch(() => {});
    });
    const timer = window.setInterval(() => void check(), 1000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [fill]);

  // The list of what can be typed out of an item: assembled from its card, so
  // that the custom fields are visible too.
  const openOptions = (item: VaultItem) => {
    setPicked(item);
    setOptCursor(0);
    const base: FillOption[] = [];
    void invoke<ItemDetail>("item_detail", { entryId: item.id })
      .then((d) => {
        const has = (k: string) => d.fields.some((f) => f.key === k);
        if (has("cardNumber")) base.push({ mode: { kind: "card" }, label: t("fill.card"), hint: d.fields.find((f) => f.key === "cardNumber")?.value ?? t("fill.cardHint"), icon: "card", hot: "⏎" });
        // "The login and the password" is offered only where keyward has
        // proven a login form: one field for each, next to each other. A
        // lone field — a search box, the first step of a two-step login —
        // takes one value at a time.
        const pair = fill?.field?.login;
        if (has("username") && has("password") && pair)
          base.push({ mode: { kind: "both" }, label: t("fill.both"), hint: pair.label ? t("fill.bothInto", { field: pair.label }) : t("fill.bothHint"), icon: "login", hot: "⏎" });
        if (has("username")) base.push({ mode: { kind: "username" }, label: t("fill.username"), hint: d.fields.find((f) => f.key === "username")?.value ?? "", icon: "identity", hot: "⌥⏎" });
        if (has("password")) base.push({ mode: { kind: "password" }, label: t("fill.password"), hint: "••••••••", icon: "key", hot: "⇧⏎" });
        if (has("totp")) base.push({ mode: { kind: "totp" }, label: t("fill.totp"), hint: t("fill.totpHint"), icon: "clock", hot: "^⏎" });
        for (const c of d.custom) {
          if (c.name.trim() === "") continue;
          base.push({ mode: { kind: "custom", name: c.name }, label: c.name, hint: c.hidden ? "••••••••" : (c.value ?? ""), icon: c.hidden ? "lock" : "note" });
        }
        setOptions(base);
      })
      .catch(() => setOptions([]));
  };

  useEffect(() => {
    // A method of its own instead of the whole history: every Cmd+K used to
    // drive the list of generated passwords into the webview as well, though
    // only the identifiers of recent items are needed.
    // The `?? []` is not decoration: an empty answer from the daemon cleared the
    // list, and at `recent.map` the whole search fell into a white screen.
    invoke<string[] | null>("recent_items")
      .then((ids) => setRecent(ids ?? []))
      .catch(() => {});
  }, []);

  const [cursor, setCursor] = useState(0);
  const list = useRef<HTMLDivElement>(null);

  const found = useMemo(() => {
    // While a tag is being typed the list of items does not jump: the hints
    // are what work.
    const q = typing ? "" : query.trim().toLowerCase();
    if (!catalog) return [];
    const pool = catalog.items.filter((i) => !i.deleted && passesTags(i, tags));
    if (!q) {
      if (tags.length > 0) return pool.slice(0, LIMIT);
      // While nothing is typed, what was opened recently. If nothing has been
      // opened yet, the favourites are shown: an empty search window is of no
      // use.
      const byId = new Map(pool.map((i) => [i.id, i]));
      const last = recent.map((id) => byId.get(id)).filter((i): i is VaultItem => i !== undefined);
      return last.length > 0 ? last.slice(0, LIMIT) : pool.filter((i) => i.favorite).slice(0, LIMIT);
    }
    return pool
      .filter(
        (i) =>
          i.name.toLowerCase().includes(q) ||
          (i.subtitle ?? "").toLowerCase().includes(q) ||
          i.uris.some((u) => u.toLowerCase().includes(q)) ||
          (i.folder_name ?? "").toLowerCase().includes(q),
      )
      .slice(0, LIMIT);
  }, [catalog, query, recent, tags, typing]);

  useEffect(() => setCursor(0), [query]);

  // From choosing a field, back to the items rather than straight out.
  useEscape(() => (picked ? setPicked(null) : onClose()));

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      // Backspace on an empty line brings the last chip back into editing.
      if (e.key === "Backspace" && query === "" && tags.length > 0 && !picked) {
        e.preventDefault();
        popTag();
        return;
      }
      // A tag is being typed: the arrows and Enter/Tab work on the hints.
      if (typingType) {
        const list = suggestions;
        if (e.key === "ArrowDown") {
          e.preventDefault();
          setSugCursor((c) => Math.min(c + 1, Math.max(0, list.length - 1)));
          return;
        }
        if (e.key === "ArrowUp") {
          e.preventDefault();
          setSugCursor((c) => Math.max(c - 1, 0));
          return;
        }
        if (e.key === "Enter" || e.key === "Tab") {
          e.preventDefault();
          addTag(typingType, list[sugCursor] ?? typingValue);
          return;
        }
        return;
      }
      if (typeHints.length > 0 && e.key === "Tab") {
        e.preventDefault();
        setQuery(`${typeHints[0]}:`);
        return;
      }
      // The second step: choosing a field.
      if (picked && fill && onFill) {
        if (e.key === "ArrowDown") {
          e.preventDefault();
          setOptCursor((c) => Math.min(c + 1, options.length - 1));
        }
        if (e.key === "ArrowUp") {
          e.preventDefault();
          setOptCursor((c) => Math.max(c - 1, 0));
        }
        if (e.key === "Enter") {
          e.preventDefault();
          // The modifiers work here too, as a short cut.
          const quick: FillMode | null = e.shiftKey ? { kind: "password" } : e.altKey ? { kind: "username" } : e.ctrlKey ? { kind: "totp" } : null;
          const mode = quick ?? options[optCursor]?.mode;
          if (mode) {
            onFill(picked.id, mode);
            onClose();
          }
        }
        return;
      }
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setCursor((c) => Math.min(c + 1, found.length - 1));
      }
      if (e.key === "ArrowUp") {
        e.preventDefault();
        setCursor((c) => Math.max(c - 1, 0));
      }
      if (e.key === "Enter" && found[cursor]) {
        e.preventDefault();
        const item = found[cursor];
        if (fill && onFill) {
          // With a modifier, at once; when the field under the cursor is
          // recognised, at once too and with what suits it; otherwise show what
          // there is to type.
          const quick: FillMode | null = e.shiftKey ? { kind: "password" } : e.altKey ? { kind: "username" } : e.ctrlKey ? { kind: "totp" } : modeForField(fill.field, item);
          if (quick) {
            onFill(item.id, quick);
            onClose();
          } else {
            openOptions(item);
          }
        } else {
          onPick(item.id);
          onClose();
        }
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [found, cursor, onPick, onClose, fill, onFill, picked, options, optCursor, query, tags, typingType, typingValue, suggestions, sugCursor, typeHints]);

  // The chosen row must not travel off the edge when moving by keyboard.
  useEffect(() => {
    list.current?.querySelector<HTMLElement>(".on")?.scrollIntoView({ block: "nearest" });
  }, [cursor]);

  return (
    <div className="scrim top" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="spot" role="dialog" aria-modal="true" aria-label={t("action.search")}>
        <label className="spot-input">
          <Icon name="search" size={16} />
          {tags.map((tg, n) => (
            <span key={`${tg.type}:${tg.value}`} className={`tag tag-${tg.type}`}>
              <b>{tg.type}:</b>
              <span>{tg.value}</span>
              <button
                type="button"
                aria-label={t("action.cancel")}
                onClick={() => {
                  setTags((cur) => cur.filter((_, i) => i !== n));
                  inputRef.current?.focus();
                }}
              >
                ×
              </button>
            </span>
          ))}
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={tags.length > 0 ? t("spot.placeholderTagged") : t("spot.placeholder")}
            spellCheck={false}
            autoFocus
          />
          {(query || tags.length > 0) && (
            <button
              type="button"
              className="inner"
              onClick={() => {
                setQuery("");
                setTags([]);
                inputRef.current?.focus();
              }}
              aria-label={t("action.cancel")}
            >
              <Icon name="close" size={12} />
            </button>
          )}
        </label>

        {/* A tag is being typed: a section of values and, below it, the search
            hints — as in a command palette: a section heading, the rows, then
            the list of tags with an explanation. */}
        {!picked && typingType && (
          <div className="spot-sug">
            <div className="spot-caption">{t(`spot.section.${typingType}` as Key)}</div>
            {suggestions.length > 0 ? (
              suggestions.map((v, n) => (
                <button
                  type="button"
                  key={v}
                  className={`spot-sug-row ${n === sugCursor ? "on" : ""}`}
                  onMouseMove={() => setSugCursor(n)}
                  onClick={() => addTag(typingType, v)}
                >
                  <Icon name={TAG_ICON[typingType]} size={13} />
                  <span>{typingType === "type" ? `${t(kindLabel(v) as Key)} · ${v}` : v}</span>
                  {n === sugCursor && <kbd>⏎</kbd>}
                </button>
              ))
            ) : (
              <div className="spot-sug-row dim">{typingValue ? t("spot.tagFree", { type: typingType, value: typingValue }) : t("spot.nothing")}</div>
            )}
          </div>
        )}
        {!picked && (typingType || typeHints.length > 0 || (query === "" && tags.length === 0 && found.length === 0)) && (
          <div className="spot-sug tips">
            <div className="spot-caption">{t("spot.tips")}</div>
            {TAG_TYPES.filter((tt) => !typingType || tt === typingType || typeHints.includes(tt)).map((tt) => (
              <button type="button" key={tt} className="spot-sug-row tip" onClick={() => setQuery(`${tt}:`)}>
                <Icon name={TAG_ICON[tt]} size={13} />
                <b>{tt}:</b>
                <span className="dash">—</span>
                <span>{t(`spot.tag.${tt}` as Key)}</span>
                {typeHints[0] === tt && <kbd>Tab</kbd>}
              </button>
            ))}
          </div>
        )}

        {fill && (
          <div className="spot-fill">
            <Icon name="login" size={13} />
            <span>
              {fill.domain ? t("spot.fillOn", { domain: fill.domain }) : t("spot.fillNoSite")}
              {fill.app ? <span className="dim"> · {fill.app}</span> : null}
              {fill.field && fill.field.kind !== "unknown" && (
                <span className="dim"> · {t(`fill.field.${fill.field.kind}` as Key)}{fill.field.label ? ` «${fill.field.label.split(" · ")[0]}»` : ""}</span>
              )}
            </span>
            {trusted === false && (
              <button type="button" className="btn small warn" onClick={() => void invoke<boolean>("autofill_request_access").then(setTrusted).catch(() => {})}>
                {t("autofill.grant")}
              </button>
            )}
          </div>
        )}
        {fill && trusted === false && <div className="spot-caption warn">{t("autofill.noAccess")}</div>}

        {picked && fill && (
          <>
            <div className="spot-caption">
              <button type="button" className="link" onClick={() => setPicked(null)}>← {t("fill.back")}</button>
              {" · "}
              {t("fill.what", { name: picked.name })}
            </div>
            <div className="spot-list">
              {options.length === 0 && <div className="spot-empty">{t("policy.reading")}</div>}
              {options.map((o, n) => (
                <button
                  type="button"
                  key={o.label + n}
                  className={`spot-row ${n === optCursor ? "on" : ""}`}
                  onMouseMove={() => setOptCursor(n)}
                  onClick={() => {
                    onFill?.(picked.id, o.mode);
                    onClose();
                  }}
                >
                  <span className="glyph"><Icon name={o.icon} size={15} /></span>
                  <span className="text">
                    <b>{o.label}</b>
                    {o.hint && <span>{o.hint}</span>}
                  </span>
                  <span className="side">{o.hot && <kbd>{o.hot}</kbd>}</span>
                </button>
              ))}
            </div>
          </>
        )}

        {!picked && !typingType && found.length > 0 && !query.trim() && (
          <div className="spot-caption">
            {tags.length > 0 ? t("spot.tagged", { n: found.length }) : recent.length > 0 ? t("spot.recent") : t("items.favorites")}
          </div>
        )}

        {!picked && !typingType && found.length > 0 && (
          <div className="spot-list" ref={list}>
            {found.map((i, n) => (
              <Row
                key={i.id}
                item={i}
                serverUrl={serverUrl}
                on={n === cursor}
                onHover={() => setCursor(n)}
                onPick={() => {
                  if (fill && onFill) {
                    const auto = modeForField(fill.field, i);
                    if (auto) {
                      onFill(i.id, auto);
                      onClose();
                    } else {
                      openOptions(i);
                    }
                  } else {
                    onPick(i.id);
                    onClose();
                  }
                }}
              />
            ))}
          </div>
        )}

        {!picked && !typingType && (query || tags.length > 0) && found.length === 0 && (
          <div className="spot-empty">{tags.length > 0 ? t("spot.nothingTagged") : t("spot.nothing")}</div>
        )}

        <div className="spot-foot">
          <span>
            <kbd>↑</kbd>
            <kbd>↓</kbd> {t("spot.move")}
          </span>
          {fill ? (
            <>
              <span>
                <kbd>⏎</kbd>{" "}
                {picked
                  ? t("spot.fill")
                  : fill.field?.kind === "password"
                    ? t("spot.fillPassword")
                    : fill.field?.kind === "totp"
                      ? t("spot.fillTotp")
                      : fill.field?.kind === "card"
                        ? t("spot.fillCard")
                      : fill.field?.kind === "username"
                        ? t("spot.fill")
                        : t("fill.choose")}
              </span>
              <span>
                <kbd>⇧⏎</kbd> {t("spot.fillPassword")}
              </span>
              <span>
                <kbd>^⏎</kbd> {t("spot.fillTotp")}
              </span>
            </>
          ) : (
            <span>
              <kbd>⏎</kbd> {t("spot.open")}
            </span>
          )}
          <span>
            <kbd>esc</kbd> {t("spot.close")}
          </span>
        </div>
      </div>
    </div>
  );
}

function Row({
  item,
  serverUrl,
  on,
  onHover,
  onPick,
}: {
  item: VaultItem;
  serverUrl: string;
  on: boolean;
  onHover: () => void;
  onPick: () => void;
}) {
  const icon = useSiteIcon(serverUrl, item.uris, item.kind === "login") ?? null;
  return (
    <button type="button" className={`spot-row ${on ? "on" : ""}`} onMouseMove={onHover} onClick={onPick}>
      <span className="glyph">
        {icon ? <img src={icon} alt="" width={16} height={16} /> : <Monogram name={item.name} size={22} />}
      </span>
      <span className="text">
        <b>{item.name}</b>
        {item.subtitle && <span>{item.subtitle}</span>}
      </span>
      <span className="side">
        <span className="chip">{t(kindLabel(kindKey(item.kind)) as Key)}</span>
      </span>
    </button>
  );
}
