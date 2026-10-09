// The window's own close, minimise and full-screen buttons, in the strip's
// left corner where the system's stood: three dots in the window's palette,
// grey while the window is not in front, their glyphs shown over the group on
// hover. ⌥ on the green one zooms instead of going full screen. Drawn only
// where the backend has a window to command; a web page has none.
import { createContext, useContext, useEffect, useState } from "react";
import "./window-buttons.css";
import type { WindowControls } from "../backend";
import { t } from "../i18n";

/// The window's controls for every strip: the gate's, the boot screen's and
/// the open window's.
export const WindowControlsContext = createContext<WindowControls | null>(null);

const GLYPH = {
  close: '<path d="M5 5l6 6M11 5l-6 6"/>',
  minimize: '<path d="M4.5 8h7"/>',
  fullscreen: '<path d="M5 11V7.5L8.5 11zM11 5v3.5L7.5 5z"/>',
} as const;

function Glyph({ d }: { d: string }) {
  return <svg viewBox="0 0 16 16" aria-hidden="true" dangerouslySetInnerHTML={{ __html: d }} />;
}

export function WindowButtons() {
  const controls = useContext(WindowControlsContext);
  const [focused, setFocused] = useState(true);
  useEffect(() => controls?.onFocus(setFocused), [controls]);
  if (!controls) return null;
  const run = (go: () => Promise<void>) => () => void go().catch((e: unknown) => console.error(e));
  return (
    <div className={`lights${focused ? "" : " away"}`} role="group" aria-label={t("win.buttons")}>
      <button type="button" className="light close" aria-label={t("win.close")} onClick={run(() => controls.close())}>
        <Glyph d={GLYPH.close} />
      </button>
      <button type="button" className="light minimize" aria-label={t("win.minimize")} onClick={run(() => controls.minimize())}>
        <Glyph d={GLYPH.minimize} />
      </button>
      <button type="button" className="light fullscreen" aria-label={t("win.fullscreen")} onClick={(e) => run(() => (e.altKey ? controls.zoom() : controls.fullscreen()))()}>
        <Glyph d={GLYPH.fullscreen} />
      </button>
    </div>
  );
}
