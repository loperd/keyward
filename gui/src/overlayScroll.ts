/// A scrollbar of our own, over the content.
///
/// The native scrollbar is physical: it appears, takes width away, and the
/// whole layout flinches. Here the native one is hidden altogether and a thin
/// one of ours is drawn over the blocks, shown while scrolling and faded out.
/// It never takes any width.
///
/// How it works: a sticky host of zero height is added to the scrollable
/// element at the top of the visible area, with an absolutely positioned thumb
/// inside it. That keeps the thumb in the scroll window with no wrappers around
/// the element itself.

const SELECTOR = ".content, .pane, .scroller, .modal .body, .context-body, .rail-body, .picker-list, .spot-list, .hist, .cm-scroller";
const HIDE_AFTER = 900;
const MIN_THUMB = 24;

type Host = HTMLElement & { __ov?: { host: HTMLDivElement; thumb: HTMLDivElement; timer: number | null; ro: ResizeObserver } };

function attach(el: Host) {
  if (el.__ov) return;
  const cs = getComputedStyle(el);
  if (!/(auto|scroll)/.test(cs.overflowY)) return;
  el.classList.add("ov-host");

  const host = document.createElement("div");
  host.className = "ov-track";
  host.setAttribute("aria-hidden", "true");
  const thumb = document.createElement("div");
  thumb.className = "ov-thumb";
  host.appendChild(thumb);
  el.prepend(host);

  const state = { host, thumb, timer: null as number | null, ro: new ResizeObserver(() => update()) };
  el.__ov = state;

  // The sticky host lives in the content box, while the bar has to stand at
  // the edge of the padding box, as the native one does. It is shifted by the
  // element's right padding.
  const pad = () => {
    const c = getComputedStyle(el);
    thumb.style.right = `${2 - parseFloat(c.paddingRight || "0")}px`;
    // In a flex column with a gap a zero-height host still adds one gap: it
    // is made up for with a negative bottom margin.
    const gap = c.display === "flex" && c.flexDirection === "column" ? parseFloat(c.rowGap || "0") || 0 : 0;
    host.style.marginBottom = gap ? `${-gap}px` : "";
  };
  pad();

  const update = () => {
    const { scrollHeight, clientHeight, scrollTop } = el;
    if (scrollHeight <= clientHeight + 1) {
      host.style.display = "none";
      return;
    }
    host.style.display = "";
    const ratio = clientHeight / scrollHeight;
    const h = Math.max(MIN_THUMB, Math.round(clientHeight * ratio) - 4);
    const maxTop = clientHeight - h - 4;
    const top = 2 + Math.round((scrollTop / (scrollHeight - clientHeight)) * maxTop);
    pad();
    thumb.style.height = `${h}px`;
    thumb.style.transform = `translateY(${top}px)`;
  };

  const show = () => {
    update();
    el.classList.add("ov-scrolling");
    if (state.timer !== null) window.clearTimeout(state.timer);
    state.timer = window.setTimeout(() => el.classList.remove("ov-scrolling"), HIDE_AFTER);
  };

  el.addEventListener("scroll", show, { passive: true });
  state.ro.observe(el);
  for (const child of el.children) if (child !== host) state.ro.observe(child);

  // Dragging the thumb: without it the bar only shows and does not steer.
  let drag: { y: number; top: number } | null = null;
  thumb.addEventListener("pointerdown", (e) => {
    drag = { y: e.clientY, top: el.scrollTop };
    thumb.setPointerCapture(e.pointerId);
    el.classList.add("ov-dragging");
    e.preventDefault();
  });
  thumb.addEventListener("pointermove", (e) => {
    if (!drag) return;
    const track = el.clientHeight - 4;
    const ratio = (el.scrollHeight - el.clientHeight) / Math.max(1, track - thumb.offsetHeight);
    el.scrollTop = drag.top + (e.clientY - drag.y) * ratio;
  });
  const end = () => {
    drag = null;
    el.classList.remove("ov-dragging");
  };
  thumb.addEventListener("pointerup", end);
  thumb.addEventListener("pointercancel", end);

  update();
}

let installed = false;

/// Attach to every scrollable area, present and future.
export function installOverlayScrollbars() {
  if (installed) return;
  installed = true;
  const scan = () => document.querySelectorAll<HTMLElement>(SELECTOR).forEach((el) => attach(el as Host));
  scan();
  const mo = new MutationObserver(() => scan());
  mo.observe(document.body, { childList: true, subtree: true });
  window.addEventListener("resize", scan);
}
