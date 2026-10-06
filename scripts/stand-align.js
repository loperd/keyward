// Alignment probe for gui/concepts/merge.html: left x of column captions, row
// leads/texts, right-edge marks, spine axes and every inspector block; reports
// only the spreads (misalignments).
(() => {
  const R = (e) => e.getBoundingClientRect();
  const vis = (e) => { const r = R(e); const s = getComputedStyle(e); return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none" && +s.opacity !== 0; };
  const textLeft = (e) => {
    // left of the first rendered text or icon inside e
    const w = document.createTreeWalker(e, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT);
    let n;
    while ((n = w.nextNode())) {
      if (n.nodeType === 3 && n.textContent.trim()) { const r = document.createRange(); r.selectNodeContents(n); const b = r.getClientRects()[0]; if (b && b.width) return b.left; }
      if (n.nodeType === 1 && (n.tagName === "svg" || n.classList.contains("kw-tile") || n.classList.contains("kw-g")) && vis(n)) return R(n).left;
    }
    return R(e).left;
  };
  const out = [];
  const spread = (label, vals) => {
    const m = new Map();
    for (const [v, who] of vals) { const k = Math.round(v); m.set(k, [...(m.get(k) ?? []), who]); }
    if (m.size > 1) out.push(`${label}: ` + [...m.entries()].map(([k, w]) => `${k}{${w.length}: ${[...new Set(w)].slice(0, 3).join(",")}}`).join("  "));
  };
  const nm = (e) => [...e.classList].slice(0, 2).join(".") || e.tagName.toLowerCase();
  // columns
  document.querySelectorAll(".kw-col").forEach((c, ci) => {
    const cl = R(c).left;
    if (c.classList.contains("kw-spined")) {
      const sp = c.querySelector(".kw-spine");
      const cx = R(sp).left + R(sp).width / 2;
      const parts = [...sp.children].filter(vis).map((x) => [R(x).left + R(x).width / 2 - cx, nm(x)]);
      spread(`spine ${ci} centre offsets`, [[0, "axis"], ...parts]);
      return;
    }
    const L = [];
    c.querySelectorAll(".kw-grp").forEach((g) => vis(g) && L.push([textLeft(g) - cl, "grp"]));
    c.querySelectorAll(".kw-row:not(.kw-empty) .kw-lead").forEach((l) => vis(l) && L.push([R(l).left - cl, "lead"]));
    c.querySelectorAll(".kw-row.kw-empty").forEach((l) => vis(l) && L.push([textLeft(l) - cl, "empty"]));
    spread(`col ${ci} left edge (caption/lead)`, L);
    spread(`col ${ci} text start`, [...c.querySelectorAll(".kw-row .kw-lbl")].filter(vis).map((l) => [R(l).left - cl, "lbl"]));
    spread(`col ${ci} right edge (marks)`, [...c.querySelectorAll(".kw-row .kw-side, .kw-grp .kw-n")].filter((x) => vis(x) && x.children.length + x.textContent.trim().length).map((x) => [R(c).right - R(x).right, nm(x)]));
  });
  // inspector
  const doc = document.querySelector(".kw-doc");
  if (doc && vis(doc)) {
    const sel = [".kw-hero > .kw-tile", ".kw-sec-h > .kw-h2", ".kw-f", ".kw-ref", ".kw-sig", ".kw-mt-h", ".kw-mt-r", ".kw-mapdoor", ".kw-note", ".kw-hist", ".kw-marks", ".kw-lhead", ".kw-lgrp", ".kw-lrow", ".kw-empty",
      ".kw-vlead", ".kw-target", ".kw-act > .kw-h1", ".kw-lede", ".kw-steps li", ".kw-delta", ".kw-vbar", ".kw-mtop", ".kw-finds", ".kw-mfoot"];
    const L = [];
    for (const s of sel) doc.querySelectorAll(s).forEach((e) => {
      if (!vis(e)) return;
      // blocks with hover pads (-8 margin) align by content, not by box
      const st = getComputedStyle(e);
      const pad = [".kw-f", ".kw-ref", ".kw-sig", ".kw-mt-h", ".kw-mt-r", ".kw-lrow", ".kw-lgrp", ".kw-lhead", ".kw-mapdoor", ".kw-mfoot", ".kw-mtop"].includes(s) ? parseFloat(st.paddingLeft) : 0;
      if (s === ".kw-ref" && e.classList.contains("kw-nest")) return;
      L.push([R(e).left + pad, s]);
    });
    spread("inspector left edge", L);
    const H = [...doc.querySelectorAll(".kw-hero-t > .kw-h1, .kw-hero-t > .kw-place, .kw-hero-t > .kw-state .kw-mk, .kw-hero-t > .kw-acts > :first-child")].filter(vis).map((e) => [e.matches(".kw-h1, .kw-place") ? textLeft(e) : R(e).left, nm(e)]);
    spread("hero text column", H);
    spread("field value start", [...doc.querySelectorAll(".kw-f .kw-v")].filter(vis).map((e) => [R(e).left, "v"]));
    spread("field actions right", [...doc.querySelectorAll(".kw-f .kw-fa")].filter((e) => e.children.length).map((e) => [R(e).right, "fa"]));
    spread("relation marks right", [...doc.querySelectorAll(".kw-ref .kw-rs")].filter(vis).map((e) => [R(e).right, "rs"]));
  }
  // vertical: first line of the lists vs the inspector's first line
  const firsts = [...document.querySelectorAll(".kw-col:not(.kw-spined) .kw-list")].map((l) => { const f = l.querySelector(".kw-row .kw-t, .kw-grp"); return f ? [R(f).top, "col"] : null; }).filter(Boolean);
  const h = doc?.querySelector(".kw-h1");
  const textTop = (e) => { const w = document.createTreeWalker(e, NodeFilter.SHOW_TEXT); let n; while ((n = w.nextNode())) if (n.textContent.trim()) { const r = document.createRange(); r.selectNodeContents(n); return r.getClientRects()[0].top - (parseFloat(getComputedStyle(n.parentElement).lineHeight) - r.getClientRects()[0].height) / 2; } return R(e).top; };
  const rowTile = [...document.querySelectorAll(".kw-col:not(.kw-spined) .kw-list")].map((l) => { const f = l.firstElementChild; if (!f) return null; return [f.classList.contains("kw-grp") ? textTop(f) : R(f.querySelector(".kw-lead") ?? f).top, f.classList.contains("kw-grp") ? "col-caption" : "col-first"]; }).filter(Boolean);
  const heroTile = doc?.querySelector(".kw-hero > .kw-tile, .kw-lhead, .kw-mtop, .kw-vlead");
  if (heroTile) spread("first line top (col first item vs inspector)", [...rowTile, [R(heroTile).top, "insp"]]);
  // the crumb menu under its «…»
  const more = document.querySelector(".kw-more"), pop = document.querySelector(".kw-pop");
  if (more && pop) out.push(`crumb menu: more.left=${Math.round(R(more).left)} pop.left=${Math.round(R(pop).left)} pop.top-more.bottom=${Math.round(R(pop).top - R(more).bottom)}`);
  // spines between open columns
  const st = [...document.querySelectorAll(".kw-col")].map((c) => (c.classList.contains("kw-spined") ? "s" : "O")).join("");
  if (/Os+O/.test(st) || /Os/.test(st)) out.push(`spine between or after open columns: ${st}`);
  return { layout: [...document.querySelectorAll(".kw-col")].map((c) => (c.classList.contains("kw-spined") ? "s" : "O")).join("") + "|insp", issues: out };
})()
