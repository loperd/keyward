// Quick look (Space): the object at a glance over the top sheet — its tile,
// name and place, the values one copies most, its state. A password stays
// dots here; only the one-time code shows, as it does on the page.
import { t, text } from "../i18n";
import { expiryText } from "../model/reasons";
import { Icon } from "./Icons";
import { Kbd, Mark, Tile, nodeLead, useCore } from "./marks";
import { ItemKind } from "../model/types";

export function QuickLook({ id, left, onClose }: { id: string; left: number; onClose: () => void }) {
  const { dir, store } = useCore();
  const n = dir.node(id);
  const it = n.item;
  const place = n.home.slice(0, -1).map((x) => text(dir.node(x).name)).join(" › ");
  const sub = it ? `${t(`kind.${it.kind}`)}${place ? ` · ${place}` : ""}` : place;
  return (
    <div className="lens-veil" style={{ left }} onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="lens">
        <div className="lens-top">
          <Icon name="eye" />
          <span>{t("ui.quickLook")}</span>
          <Kbd>{t("ui.space")}</Kbd>
        </div>
        <header className="hero">
          <Tile lead={nodeLead(dir, id, true)} xl />
          <div className="hero-t">
            <h1 className="h1">{text(n.name)}</h1>
            <div className="place">{sub}</div>
          </div>
        </header>
        {it?.kind === ItemKind.Login && (
          <>
            {it.subtitle && (
              <div className="lsrow">
                <span className="k">{t("field.username")}</span>
                <span className="v mono">{it.subtitle}</span>
                <Kbd>⌘1</Kbd>
              </div>
            )}
            <div className="lsrow">
              <span className="k">{t("field.password")}</span>
              <span className="v dots">••••••••••••</span>
              <Kbd>⌘2</Kbd>
            </div>
          </>
        )}
        {it?.kind === ItemKind.Card && (
          <>
            <div className="lsrow">
              <span className="k">{t("field.cardNumber")}</span>
              <span className="v">
                <span className="dots">••••</span> <span className="mono">{(it.subtitle ?? "").slice(-4)}</span>
              </span>
              <Kbd>⌘1</Kbd>
            </div>
            {it.expires && (
              <div className="lsrow">
                <span className="k">{t("field.expiry")}</span>
                <span className="v mono">{expiryText(it.expires)}</span>
                <Kbd>⌘2</Kbd>
              </div>
            )}
          </>
        )}
        {it && it.kind !== ItemKind.Login && it.kind !== ItemKind.Card && (
          <div className="lsrow">
            <span className="k">{t("ui.brief")}</span>
            <span className="v">{n.sub ? text(n.sub) : ""}</span>
          </div>
        )}
        <div className="lens-foot">
          {it ? <Mark level={n.level} words={n.why!} /> : <span />}
          <button
            type="button"
            className="btn quiet"
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
