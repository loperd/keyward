// Quick look (Space): the object at a glance over the top sheet — its tile,
// name and place, the values one copies most, its state. A password stays
// dots here; only the one-time code shows, as it does on the page.
import { t, text } from "../i18n";
import { expiryText } from "../model/reasons";
import { Icon } from "./Icons";
import { Kbd, Mark, Tile, nodeLead, useCore } from "./marks";
import { TotpCode } from "./secret";
import { ItemKind } from "../model/types";

export function QuickLook({ id, left, onClose }: { id: string; left: number; onClose: () => void }) {
  const { dir, store } = useCore();
  const n = dir.node(id);
  const it = n.item;
  const place = n.home.slice(0, -1).map((x) => text(dir.node(x).name)).join(" › ");
  const sub = it ? `${t(`kind.${it.kind}`)}${place ? ` · ${place}` : ""}` : place;
  return (
    <div className="kw-lens-veil" style={{ left }} onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="kw-lens">
        <div className="kw-lens-top">
          <Icon name="eye" />
          <span>{t("ui.quickLook")}</span>
          <Kbd>{t("ui.space")}</Kbd>
        </div>
        <header className="kw-hero">
          <Tile lead={nodeLead(dir, id, true)} xl />
          <div className="kw-hero-t">
            <h1 className="kw-h1">{text(n.name)}</h1>
            <div className="kw-place">{sub}</div>
          </div>
        </header>
        {it?.kind === ItemKind.Login && (
          <>
            {it.subtitle && (
              <div className="kw-lsrow">
                <span className="kw-k">{t("field.username")}</span>
                <span className="kw-v kw-mono">{it.subtitle}</span>
                <Kbd>⌘1</Kbd>
              </div>
            )}
            <div className="kw-lsrow">
              <span className="kw-k">{t("field.password")}</span>
              <span className="kw-v kw-dots">••••••••••••</span>
              <Kbd>⌘2</Kbd>
            </div>
            {it.hasTotp && (
              <div className="kw-lsrow">
                <span className="kw-k">{t("field.totp")}</span>
                <span className="kw-v kw-code">
                  <TotpCode itemId={it.id} />
                </span>
                <Kbd>⌘3</Kbd>
              </div>
            )}
          </>
        )}
        {it?.kind === ItemKind.Card && (
          <>
            <div className="kw-lsrow">
              <span className="kw-k">{t("field.cardNumber")}</span>
              <span className="kw-v">
                <span className="kw-dots">••••</span> <span className="kw-mono">{(it.subtitle ?? "").slice(-4)}</span>
              </span>
              <Kbd>⌘1</Kbd>
            </div>
            {it.expires && (
              <div className="kw-lsrow">
                <span className="kw-k">{t("field.expiry")}</span>
                <span className="kw-v kw-mono">{expiryText(it.expires)}</span>
                <Kbd>⌘2</Kbd>
              </div>
            )}
          </>
        )}
        {it && it.kind !== ItemKind.Login && it.kind !== ItemKind.Card && (
          <div className="kw-lsrow">
            <span className="kw-k">{t("ui.brief")}</span>
            <span className="kw-v">{n.sub ? text(n.sub) : ""}</span>
          </div>
        )}
        <div className="kw-lens-foot">
          {it ? <Mark level={n.level} words={n.why!} /> : <span />}
          <button
            type="button"
            className="kw-btn kw-quiet"
            onClick={() => {
              onClose();
              store.go(id);
            }}
          >
            {t("ui.open")}
            <Kbd>↵</Kbd>
          </button>
        </div>
      </div>
    </div>
  );
}
