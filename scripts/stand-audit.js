// A layout audit of the declared screens, run in the page by
// `scripts/stand-shot.mjs` (`{"audit": true}`). It measures instead of
// looking: what spills out of its border, spacing off the 8px grid, cramped
// padding in bordered boxes, blocks of one level that start at different
// left edges, a tab highlight that is not under its tab, a head whose title
// and actions are not on one line.
//
// The audited containers default to the declared screens (.dv-screen,
// .dv-drawer, .modal); a caller picks others by setting
// `window.__kwAuditScope` to a CSS selector list before running it (the UI
// check scopes it to the core's containers).
(() => {
  const containers = window.__kwAuditScope ?? ".dv-screen, .dv-drawer, .modal";
  const scope = [...new Set(containers.split(",").flatMap((c) => [...document.querySelectorAll(`${c.trim()} *`)]))];
  const out = { spill: [], grid: [], cramped: [], edges: [], tabs: [], head: [], pads: [], type: [] };
  const name = (e) => {
    const c = [...e.classList].slice(0, 3).join(".");
    const t = (e.textContent || "").trim().slice(0, 24);
    return `${e.tagName.toLowerCase()}${c ? "." + c : ""}${t ? ` "${t}"` : ""}`;
  };
  const px = (v) => parseFloat(v) || 0;
  const visible = (e) => {
    const r = e.getBoundingClientRect();
    const s = getComputedStyle(e);
    return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none" && s.opacity !== "0";
  };
  const seen = new Set();
  const push = (list, key, item) => {
    if (seen.has(list + key)) return;
    seen.add(list + key);
    out[list].push(item);
  };
  for (const e of scope) {
    if (!visible(e)) continue;
    const s = getComputedStyle(e);
    const r = e.getBoundingClientRect();
    const bordered = px(s.borderTopWidth) > 0 && px(s.borderLeftWidth) > 0 && s.borderTopStyle !== "none";
    // 1. Spill: a child's box outside a bordered parent's box, or a text
    // that overflows its own box while the box does not scroll.
    if (bordered && s.overflow === "visible") {
      for (const c of e.children) {
        if (!visible(c) || getComputedStyle(c).position === "fixed") continue;
        const cr = c.getBoundingClientRect();
        if (cr.top < r.top - 1 || cr.bottom > r.bottom + 1 || cr.left < r.left - 1 || cr.right > r.right + 1)
          push("spill", name(e) + name(c), `${name(c)} spills out of ${name(e)} (${Math.round(cr.bottom - r.bottom)}px below, ${Math.round(cr.right - r.right)}px right)`);
      }
    }
    if ((e.scrollHeight > e.clientHeight + 1 || e.scrollWidth > e.clientWidth + 1) && !/(auto|scroll|hidden|clip)/.test(s.overflow + s.overflowX + s.overflowY) && e.children.length === 0 && (e.textContent || "").trim())
      push("spill", name(e), `${name(e)}: its text overflows a fixed box (${e.scrollHeight}>${e.clientHeight})`);
    // 2. Grid: paddings, margins and gaps off 4/8.
    for (const [prop, v] of [
      ["padding-top", s.paddingTop], ["padding-right", s.paddingRight], ["padding-bottom", s.paddingBottom], ["padding-left", s.paddingLeft],
      ["margin-top", s.marginTop], ["margin-bottom", s.marginBottom], ["margin-left", s.marginLeft], ["margin-right", s.marginRight],
      ["gap", s.rowGap], ["column-gap", s.columnGap],
    ]) {
      const n = px(v);
      if (n > 0 && n % 4 !== 0) push("grid", name(e) + prop, `${name(e)} ${prop}: ${v}`);
      else if (n > 4 && n % 8 !== 0 && !prop.startsWith("margin")) push("grid", name(e) + prop, `${name(e)} ${prop}: ${v} (not ×8)`);
    }
    // 3. Cramped: a bordered box with text inside and less than 8px of air.
    if (bordered && (e.textContent || "").trim() && r.height > 20) {
      const min = Math.min(px(s.paddingLeft), px(s.paddingRight));
      if (min < 8 && !e.matches("input,textarea,button.icon-only,.btn.icon-only,.dot,.chip,.dv-chip"))
        push("cramped", name(e), `${name(e)}: ${min}px inside its border`);
    }
  }
  // 7. Pads: every container's padding, grouped — the spread is the finding.
  const pads = new Map();
  for (const e of scope) {
    if (!visible(e) || e.children.length === 0 || !/^(DIV|SECTION|HEADER|FORM|LABEL)$/.test(e.tagName)) continue;
    const s = getComputedStyle(e);
    const p = [s.paddingTop, s.paddingRight, s.paddingBottom, s.paddingLeft].map((v) => Math.round(px(v))).join(" ");
    if (p === "0 0 0 0") continue;
    const k = [...e.classList][0] ?? e.tagName.toLowerCase();
    pads.set(`${k}: ${p}`, (pads.get(`${k}: ${p}`) ?? 0) + 1);
  }
  out.pads = [...pads.entries()].map(([k, n]) => `${k} ×${n}`).sort();
  // 8. Type: every text style in use — size/weight/family/spacing — with a
  // sample; one design has few of them.
  const type = new Map();
  for (const e of [...scope, ...document.querySelectorAll(".head *, .context-head *")]) {
    if (!visible(e)) continue;
    const own = [...e.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim());
    if (!own) continue;
    const s = getComputedStyle(e);
    const fam = /mono/i.test(s.fontFamily) ? "mono" : "sans";
    const k = `${s.fontSize}/${s.fontWeight} ${fam}${s.letterSpacing !== "normal" ? " ls" + s.letterSpacing : ""}${s.textTransform === "uppercase" ? " CAPS" : ""}`;
    const cur = type.get(k) ?? { n: 0, sample: name(e) };
    cur.n++;
    type.set(k, cur);
  }
  out.type = [...type.entries()].sort((a, b) => b[1].n - a[1].n).map(([k, v]) => `${k} ×${v.n}  e.g. ${v.sample}`);
  // 4. Edges: the screen's own blocks should share one left edge.
  const screen = document.querySelector(".dv-screen");
  if (screen) {
    const blocks = [...screen.querySelectorAll(":scope > *, .dv-tabs > *, .dv-filters > *, .screen-head, .dv-section, .dv-cards, .dv-rows, .dv-table-wrap")].filter((b) => visible(b) && !b.closest(".dv-drawer"));
    const lefts = new Map();
    for (const b of blocks) {
      const l = Math.round(b.getBoundingClientRect().left);
      lefts.set(l, [...(lefts.get(l) ?? []), name(b)]);
    }
    if (lefts.size > 1) out.edges.push(...[...lefts.entries()].map(([l, n]) => `left ${l}: ${n.slice(0, 4).join(", ")}`));
  }
  // 5. Tabs: the highlight under the active tab.
  for (const seg of document.querySelectorAll(".segmented, .seg, [role=tablist]")) {
    const on = seg.querySelector('[aria-selected="true"], .on');
    const ind = seg.querySelector(":scope > .ink");
    if (on && ind) {
      const a = on.getBoundingClientRect();
      const b = ind.getBoundingClientRect();
      if (Math.abs(a.left - b.left) > 1 || Math.abs(a.width - b.width) > 1)
        out.tabs.push(`${name(seg)}: highlight at ${Math.round(b.left)}/${Math.round(b.width)}, tab at ${Math.round(a.left)}/${Math.round(a.width)}`);
    }
  }
  // 6. Head: the title (or switcher) and the actions on one line.
  for (const head of document.querySelectorAll(".screen-head-row, .modal > header")) {
    const title = head.querySelector(".screen-head-title, .dv-switch-pill, h3");
    const btn = head.querySelector(":scope > .btn, :scope > button");
    if (title && btn) {
      const a = title.getBoundingClientRect();
      const b = btn.getBoundingClientRect();
      const d = Math.round(a.top + a.height / 2 - (b.top + b.height / 2));
      if (Math.abs(d) > 1) out.head.push(`${name(head)}: title centre ${d}px off the actions' centre`);
    }
  }
  return out;
})();
