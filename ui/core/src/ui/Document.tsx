// A document drawn: the hero, then sections of fields, relations, signal
// lines, a members table, a door to a map. It draws a `DocSpec` and decides
// nothing: what a page says is the builder's (doc/build.ts) or the plugin's.
import { PreviewKind } from "../verbs/spec";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { t, text, type Text } from "../i18n";
import { type Act, type Action, type Block, type DocSpec, type Hero, type Lead, type MarkSpec, type Section, LeadTile, LiveBlock } from "../doc/spec";
import { type Member, MemberStatus, Level } from "../model/types";
import { fieldLabel } from "../doc/build";
import { Icon } from "./Icons";
import { BtnIcon, Glyph, IconButton, Mark, Spinner, Tile, nodeLead, useCore } from "./marks";
import { useAct } from "./act";
import { useFeedback, Phase } from "./feedback";
import { useRowMotion, withGone } from "./row-motion";
import { dotsFor, useReportUnlessLocked, useReveal } from "./secret";
import { BlockSkeleton } from "./Loading";
import { SettingRowView } from "./settings-context";
import { BrowsersRow, ExtensionsList } from "./Extensions";
import { ProfileView } from "./Profile";
import { EmailChange, TwoFactorPanel } from "./TwoFactor";
import { useSettingsMaybe } from "./settings-context";

const say = (x: Text) => text(x);

/// A button's act with its own answer: busy while the act's call runs, a
/// check for a moment when it ends without moving the line (a copy).
function usePress(): { phase: Phase; press: (a: Act) => void } {
  const run = useAct();
  const { report } = useCore();
  const fb = useFeedback(report);
  return { phase: fb.phase, press: (a: Act) => fb.run(() => run(a)) };
}

/// An icon button that runs an act and answers it.
function ActIconButton({ icon, tip, act }: { icon: string; tip: string; act: Act }) {
  const { phase, press } = usePress();
  return <IconButton icon={icon} tip={tip} phase={phase} onClick={() => press(act)} />;
}

/// A worded button that runs an act and answers it; its icon is what turns.
function ActButton({ act, icon, className, children }: { act: Act; icon?: string | undefined; className: string; children: ReactNode }) {
  const { phase, press } = usePress();
  return (
    <button
      type="button"
      className={`${className}${phase === Phase.Done ? " done" : ""}`}
      aria-busy={phase === Phase.Busy || undefined}
      disabled={phase === Phase.Busy}
      onClick={(e) => {
        e.stopPropagation();
        press(act);
      }}
    >
      {icon ? <BtnIcon icon={icon} phase={phase} /> : phase === Phase.Busy ? <Spinner /> : null}
      {children}
    </button>
  );
}

export function Place({ ids, what }: { ids: string[]; what?: Text | undefined }) {
  const { dir, store } = useCore();
  const parts: ReactNode[] = [];
  ids.forEach((id, i) => {
    if (i) parts.push(<span key={`s${i}`} className="sl">›</span>);
    parts.push(
      <a key={id} onClick={() => store.go(id)}>
        {text(dir.node(id).name)}
      </a>,
    );
  });
  if (what) {
    if (ids.length) parts.push(<span key="dot" className="sl">·</span>);
    parts.push(<span key="what">{say(what)}</span>);
  }
  return <div className="place">{parts}</div>;
}

/// The verbs a node offers beyond the buttons its page already shows: not a
/// copy (a button does that at once, a preview for it is a detour), and not
/// what works anywhere (locking is the strip's).
function menuVerbs(query: ReturnType<typeof useCore>["query"], dir: ReturnType<typeof useCore>["dir"], node: string | null, shown: ReadonlySet<string>) {
  const n = node && dir.has(node) ? dir.node(node) : null;
  if (!n) return [];
  return query.verbs.filter((v) => {
    if (!v.preview || !v.applies(n) || v.applies(null) || shown.has(v.id)) return false;
    const p = v.preview(dir, n.id, "");
    return !(p.kind === PreviewKind.Ready && "copy" in p.effect);
  });
}

/// "More": the node's other verbs, each opening its preview on the line.
function MoreMenu({ tip, verbs }: { tip: string; verbs: ReturnType<typeof menuVerbs> }) {
  const { store } = useCore();
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLSpanElement>(null);
  useEffect(() => {
    if (!open) return;
    const away = (e: PointerEvent) => {
      if (box.current && !box.current.contains(e.target as globalThis.Node)) setOpen(false);
    };
    const esc = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        setOpen(false);
      }
    };
    document.addEventListener("pointerdown", away);
    window.addEventListener("keydown", esc, true);
    return () => {
      document.removeEventListener("pointerdown", away);
      window.removeEventListener("keydown", esc, true);
    };
  }, [open]);
  return (
    <span className="more" ref={box}>
      <IconButton icon="more" tip={tip} onClick={() => setOpen(!open)} className={open ? "on" : undefined} />
      {open && (
        <span className="more-menu" role="menu">
          {verbs.map((v) => (
            <button
              key={v.id}
              type="button"
              role="menuitem"
              className="mrow"
              onClick={() => {
                // The menu closes first: the page fading out under the
                // preview keeps no open menu in its picture.
                setOpen(false);
                requestAnimationFrame(() => store.verb(v.id));
              }}
            >
              <span className="ic">
                <Icon name={v.icon ?? "verb"} />
              </span>
              <span className="lb">{say(v.name)}</span>
            </button>
          ))}
        </span>
      )}
    </span>
  );
}

function HeroView({ hero }: { hero: Hero }) {
  const { dir, backend } = useCore();
  const lead: Lead = hero.lead.tile === LeadTile.Node ? nodeLead(dir, hero.lead.id, true) : hero.lead;
  // A button for a verb the window does not have (an app without writes has
  // no `> edit`), or for what the app cannot do (open a link), is not drawn.
  const { query } = useCore();
  const offered = (a: Action | undefined) =>
    !!a &&
    (!("verb" in a.act) || query.verbs.some((v) => "verb" in a.act && v.id === a.act.verb)) &&
    (!("open" in a.act) || !!backend.openUrl) &&
    (!("copyText" in a.act) || !!backend.copyText);
  const primary = offered(hero.primary) ? hero.primary : undefined;
  const shown = new Set([primary, ...(hero.more ?? [])].flatMap((a) => (a && "verb" in a.act ? [a.act.verb] : [])));
  const extra = menuVerbs(query, dir, hero.lead.tile === LeadTile.Node ? hero.lead.id : null, shown);
  // "More" with nothing more to offer is not drawn.
  const more = hero.more?.filter((a) => offered(a) && (!("menu" in a.act) || extra.length > 0));
  return (
    <header className="hero">
      <Tile lead={lead} xl />
      <div className="hero-t">
        <h1 className={`h1${hero.mono ? " mono" : ""}`}>{say(hero.title)}</h1>
        <Place ids={hero.place} what={hero.what} />
        {hero.state && (
          <div className="state">
            <Mark level={hero.state.level} words={hero.state.text} />
          </div>
        )}
        {(primary || more?.length) && (
          <div className="acts">
            {primary && (
              <ActButton act={primary.act} icon={primary.icon} className="btn solid">
                {say(primary.label)}
              </ActButton>
            )}
            {more?.map((a, i) =>
              "menu" in a.act ? (
                <MoreMenu key={i} tip={say(a.label)} verbs={extra} />
              ) : a.off ? (
                <IconButton key={i} icon={a.icon} tip={`${say(a.label)} — ${say(a.off)}`} disabled />
              ) : (
                <ActIconButton key={i} icon={a.icon} tip={say(a.label)} act={a.act} />
              ),
            )}
          </div>
        )}
      </div>
    </header>
  );
}

function SectionView({ s }: { s: Section }) {
  const run = useAct();
  // A section whose skeleton gave way to its content fades the content in.
  const waited = useRef(false);
  const waiting = s.blocks.some((b) => "skeleton" in b);
  if (waiting) waited.current = true;
  return (
    <section className={`sec${!waiting && waited.current ? " arrived" : ""}`}>
      <div className="sec-h">
        <h2 className="h2">{say(s.title)}</h2>
        {s.count !== undefined && <span className="n">{typeof s.count === "number" ? s.count : say(s.count)}</span>}
        {s.aside && (
          <span className="aside">
            {"none" in s.aside.act ? (
              say(s.aside.label)
            ) : s.aside.icon ? (
              <ActButton act={s.aside.act} icon={s.aside.icon} className="btn">
                {say(s.aside.label)}
              </ActButton>
            ) : (
              <a onClick={() => run(s.aside!.act)}>{say(s.aside.label)}</a>
            )}
          </span>
        )}
      </div>
      {s.blocks.map((b, i) => (
        <BlockView key={i} b={b} />
      ))}
    </section>
  );
}

const copyTip = () => t("ui.copy");

function SecretField({ b }: { b: Extract<Block, { secret: unknown }> }) {
  const { backend, revealTick, reprompt } = useCore();
  const r = useReveal(b.secret.secret);
  const fail = useReportUnlessLocked();
  // The hero's "Open" asks every secret of the page to show itself — but an
  // item that asks for the master password again is never shown in bulk:
  // its fields open one by one, each through the prompt. Only an ask made
  // while the field is on the page counts: a field drawn later (another
  // item's page) does not show itself because of an "Open" pressed before.
  const seenTick = useRef(revealTick);
  useEffect(() => {
    if (revealTick === seenTick.current) return;
    seenTick.current = revealTick;
    const ref = b.secret.secret;
    if (ref && !reprompt.isGuarded(ref.itemId)) r.show().catch(fail);
    // Only a new ask shows it again; the field's own state is its own.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [revealTick]);
  const f = b.secret;
  const tip = backend.caps.biometric ? t("ui.revealBiometric") : t("ui.reveal");
  return (
    <div className="f">
      <span className="k">{say(fieldLabel(f))}</span>
      <span className="v">{r.value !== null ? <span className="shown">{r.value}</span> : <span>
            <span className="dots">{dotsFor(f.key)}</span>
            {b.tail && <span className="mono"> {b.tail}</span>}
          </span>}</span>
      <span className={`fa${r.value !== null ? " held" : ""}`}>
        <IconButton icon="eye" tip={r.value !== null ? t("ui.hide") : tip} onClick={r.toggle} phase={r.busy ? Phase.Busy : Phase.Idle} />
        {f.secret && <ActIconButton icon="copy" tip={copyTip()} act={{ copy: f.secret }} />}
      </span>
    </div>
  );
}

function RefView({ b }: { b: Extract<Block, { ref: string | null }> }) {
  const { store } = useCore();
  const run = useAct();
  const click = () => {
    if (b.act) run(b.act);
    else if (b.ref) store.go(b.ref);
  };
  return (
    <div className={`ref${b.off ? " off" : ""}${b.nest ? " nest" : ""}`} onClick={click}>
      <Tile lead={b.lead} />
      <span className={`rt${b.mono ? " mono" : ""}`}>{say(b.title)}</span>
      <span className="rc">{b.context ? say(b.context) : ""}</span>
      <span className="rs">
        {b.perm && <span className="perm">{say(b.perm)}</span>}
        {b.glyph && <Glyph level={b.glyph.level} words={b.glyph.text} />}
        {b.mark && <Mark level={b.mark.level} words={b.mark.text} />}
      </span>
    </div>
  );
}

function SigView({ b }: { b: Extract<Block, { sig: unknown }> }) {
  const run = useAct();
  const { query } = useCore();
  // A way out the window has no verb for is not offered.
  const action = b.action && (!("verb" in b.action.act) || query.verbs.some((v) => "verb" in b.action!.act && v.id === b.action!.act.verb)) ? b.action : undefined;
  return (
    <div className="sig" onClick={b.go ? () => run(b.go!) : undefined}>
      <Glyph level={b.sig} />
      <span className="tx">
        <b className={b.mono ? "mono" : undefined}>{say(b.title)}</b>
        {b.sub && <span>{say(b.sub)}</span>}
      </span>
      {action ? (
        <ActButton act={action.act} className="btn quiet">
          {say(action.label)}
        </ActButton>
      ) : (
        <span />
      )}
    </div>
  );
}

const statusMark = (m: Member): MarkSpec =>
  m.status === MemberStatus.Confirmed ? { level: Level.Healthy, text: { key: "status.confirmed" } } : m.status === MemberStatus.Accepted ? { level: Level.Action, text: { key: "status.acceptedAwaits" } } : { level: Level.Unknown, text: { key: "status.invited" } };
const tfaMark = (m: Member): MarkSpec =>
  m.twoFactor === null ? { level: Level.Unknown, text: { key: "doc.unknown" } } : m.twoFactor ? { level: Level.Healthy, text: { key: "doc.on" } } : { level: Level.Warning, text: { key: "doc.off" } };

const memberId = (m: Member) => m.id;
const memberSig = (m: Member) => `${m.name ?? ""}\u0000${m.email}\u0000${m.role}\u0000${m.status}\u0000${m.twoFactor}\u0000${m.accessAll}`;

function MembersTable({ members }: { members: Member[] }) {
  const { store, dir } = useCore();
  // An invite, a change of role, a confirm light their row up; a member
  // removed folds away, while the graph still knows them to draw.
  const motion = useRowMotion(members, memberId, memberSig, true);
  const drawn = withGone(members, motion.gone).filter((r) => !r.gone || dir.has(`member:${r.item.id}`));
  return (
    <>
      <div className="mt-h">
        <span />
        <span>{t("ui.th.name")}</span>
        <span>{t("ui.th.role")}</span>
        <span>{t("ui.th.status")}</span>
        <span>{t("ui.th.tfa")}</span>
        <span>{t("ui.th.access")}</span>
      </div>
      {drawn.map(({ item: m, gone }) => {
        const st = statusMark(m);
        const tf = tfaMark(m);
        const move = gone ? " leave" : motion.fresh(m.id) ? " arrive" : "";
        return (
          <div
            key={`${gone ? "gone:" : ""}${m.id}`}
            className={`mt-r calm${move}`}
            onClick={gone ? undefined : () => store.go(`member:${m.id}`)}
            onAnimationEnd={(e) => {
              if (move && e.target === e.currentTarget) motion.settle(m.id);
            }}
          >
            <Tile lead={{ tile: LeadTile.Node, id: `member:${m.id}` }} />
            <span className="who">
              <b>
                {m.name ?? m.email}
                {m.isYou && <span className="me-tag">{t("ui.you")}</span>}
              </b>
              <span>{m.email}</span>
            </span>
            <span className="role">{t(`role.${m.role}`)}</span>
            <Mark level={st.level} words={st.text} />
            <Mark level={tf.level} words={tf.text} />
            <span className={`all${m.accessAll ? "" : " no"}`}>{t(m.accessAll ? "ui.accessAll" : "ui.accessAssigned")}</span>
          </div>
        );
      })}
    </>
  );
}

function BlockView({ b }: { b: Block }) {
  const run = useAct();
  const { report } = useCore();
  const profileTick = useSettingsMaybe()?.accountTick ?? 0;
  if ("setting" in b) return <SettingRowView setting={b.setting} report={report} />;
  if ("live" in b) return b.live === LiveBlock.Extensions ? <ExtensionsList /> : b.live === LiveBlock.TwoFactor ? <TwoFactorPanel /> : b.live === LiveBlock.Email ? <EmailChange /> : b.live === LiveBlock.Browsers ? <BrowsersRow /> : <ProfileView version={profileTick} />;
  if ("secret" in b) return <SecretField b={b} />;
  if ("field" in b)
    return (
      <div className="f">
        <span className="k">{say(b.field)}</span>
        <span className="v">
          {say(b.value) !== "" && <span className={b.mono ? "mono" : b.dim ? "dim" : undefined}>{say(b.value)}</span>}
          {b.faint && <span className="faint">{say(b.faint)}</span>}
          {b.mark && <Mark level={b.mark.level} words={b.mark.text} />}
        </span>
        <span className="fa">
          {b.copy && <ActIconButton icon="copy" tip={copyTip()} act={b.copy as Act} />}
          {b.open && <IconButton icon="ext" tip={t("ui.open")} />}
        </span>
      </div>
    );
  if ("ref" in b) return <RefView b={b} />;
  if ("sig" in b) return <SigView b={b} />;
  if ("marks" in b)
    return (
      <div className="marks">
        {b.marks.map((m, i) => (
          <Mark key={i} level={m.level} words={m.text} />
        ))}
      </div>
    );
  if ("members" in b) return <MembersTable members={b.members} />;
  if ("skeleton" in b) return <BlockSkeleton kind={b.skeleton} rows={b.rows} words={b.words} />;
  if ("mapdoor" in b)
    return (
      <div className="mapdoor" onClick={() => run({ map: b.mapdoor })}>
        <span className="ic">
          <Icon name="map" />
        </span>
        <span className="tx">
          <b>{say(b.title)}</b>
          <span>{say(b.sub)}</span>
        </span>
        <button type="button" className="btn quiet">
          <Icon name="map" />
          {t("ui.openMap")}
        </button>
      </div>
    );
  return <p className="para">{say(b.para)}</p>;
}

export function DocumentView({ doc }: { doc: DocSpec }) {
  return (
    <>
      <HeroView hero={doc.hero} />
      {doc.sections.map((s, i) => (
        <SectionView key={i} s={s} />
      ))}
      {doc.note && (
        <p className="note">
          <Icon name="info" />
          <span>{say(doc.note)}</span>
        </p>
      )}
      {doc.history && (
        <div className="hist">
          <Icon name="clock" />
          <span>{say(doc.history)}</span>
        </div>
      )}
    </>
  );
}
