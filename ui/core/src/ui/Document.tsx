// A document drawn: the hero, then sections of fields, relations, signal
// lines, a members table, a door to a map. It draws a `DocSpec` and decides
// nothing: what a page says is the builder's (doc/build.ts) or the plugin's.
import { useEffect, useRef, type ReactNode } from "react";
import { t, text, type Text } from "../i18n";
import { type Act, type Action, type Block, type DocSpec, type Hero, type Lead, type MarkSpec, type Section, LeadTile } from "../doc/spec";
import { type Member, MemberStatus, Level } from "../model/types";
import { fieldLabel } from "../doc/build";
import { Icon } from "./Icons";
import { BtnIcon, Glyph, IconButton, Mark, Spinner, Tile, nodeLead, useCore } from "./marks";
import { useAct } from "./act";
import { useFeedback, Phase } from "./feedback";
import { useRowMotion, withGone } from "./row-motion";
import { dotsFor, TotpCode, useReportUnlessLocked, useReveal } from "./secret";
import { BlockSkeleton } from "./Loading";
import { SettingRowView } from "./settings-context";

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
      className={`${className}${phase === Phase.Done ? " kw-done" : ""}`}
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
    if (i) parts.push(<span key={`s${i}`} className="kw-sl">›</span>);
    parts.push(
      <a key={id} onClick={() => store.go(id)}>
        {text(dir.node(id).name)}
      </a>,
    );
  });
  if (what) {
    if (ids.length) parts.push(<span key="dot" className="kw-sl">·</span>);
    parts.push(<span key="what">{say(what)}</span>);
  }
  return <div className="kw-place">{parts}</div>;
}

function HeroView({ hero }: { hero: Hero }) {
  const { dir } = useCore();
  const lead: Lead = hero.lead.tile === LeadTile.Node ? nodeLead(dir, hero.lead.id, true) : hero.lead;
  // A button for a verb the window does not have (an app without writes has
  // no `> edit`) is not drawn.
  const { query } = useCore();
  const offered = (a: Action | undefined) => !!a && (!("verb" in a.act) || query.verbs.some((v) => "verb" in a.act && v.id === a.act.verb));
  const primary = offered(hero.primary) ? hero.primary : undefined;
  const more = hero.more?.filter(offered);
  return (
    <header className="kw-hero">
      <Tile lead={lead} xl />
      <div className="kw-hero-t">
        <h1 className={`kw-h1${hero.mono ? " kw-mono" : ""}`}>{say(hero.title)}</h1>
        <Place ids={hero.place} what={hero.what} />
        {hero.state && (
          <div className="kw-state">
            <Mark level={hero.state.level} words={hero.state.text} />
          </div>
        )}
        {(primary || more?.length) && (
          <div className="kw-acts">
            {primary && (
              <ActButton act={primary.act} icon={primary.icon} className="kw-btn kw-solid">
                {say(primary.label)}
              </ActButton>
            )}
            {more?.map((a, i) => <ActIconButton key={i} icon={a.icon} tip={say(a.label)} act={a.act} />)}
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
    <section className={`kw-sec${!waiting && waited.current ? " kw-arrived" : ""}`}>
      <div className="kw-sec-h">
        <h2 className="kw-h2">{say(s.title)}</h2>
        {s.count !== undefined && <span className="kw-n">{typeof s.count === "number" ? s.count : say(s.count)}</span>}
        {s.aside && (
          <span className="kw-aside">
            {"none" in s.aside.act ? (
              say(s.aside.label)
            ) : s.aside.icon ? (
              <ActButton act={s.aside.act} icon={s.aside.icon} className="kw-btn">
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
    <div className="kw-f">
      <span className="kw-k">{say(fieldLabel(f))}</span>
      <span className="kw-v">{r.value !== null ? <span className="kw-shown">{r.value}</span> : <span>
            <span className="kw-dots">{dotsFor(f.key)}</span>
            {b.tail && <span className="kw-mono"> {b.tail}</span>}
          </span>}</span>
      <span className={`kw-fa${r.value !== null ? " kw-held" : ""}`}>
        <IconButton icon="eye" tip={r.value !== null ? t("ui.hide") : tip} onClick={r.toggle} phase={r.busy ? Phase.Busy : Phase.Idle} />
        {f.secret && <ActIconButton icon="copy" tip={copyTip()} act={b.verb ? { verb: b.verb } : { copy: f.secret }} />}
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
    <div className={`kw-ref${b.off ? " kw-off" : ""}${b.nest ? " kw-nest" : ""}`} onClick={click}>
      <Tile lead={b.lead} />
      <span className={`kw-rt${b.mono ? " kw-mono" : ""}`}>{say(b.title)}</span>
      <span className="kw-rc">{b.context ? say(b.context) : ""}</span>
      <span className="kw-rs">
        {b.perm && <span className="kw-perm">{say(b.perm)}</span>}
        {b.glyph && <Glyph level={b.glyph.level} words={b.glyph.text} />}
        {b.mark && <Mark level={b.mark.level} words={b.mark.text} />}
      </span>
    </div>
  );
}

function SigView({ b }: { b: Extract<Block, { sig: unknown }> }) {
  const run = useAct();
  return (
    <div className="kw-sig" onClick={b.go ? () => run(b.go!) : undefined}>
      <Glyph level={b.sig} />
      <span className="kw-tx">
        <b className={b.mono ? "kw-mono" : undefined}>{say(b.title)}</b>
        {b.sub && <span>{say(b.sub)}</span>}
      </span>
      {b.action ? (
        <ActButton act={b.action.act} className="kw-btn kw-quiet">
          {say(b.action.label)}
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
      <div className="kw-mt-h">
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
        const move = gone ? " kw-leave" : motion.fresh(m.id) ? " kw-arrive" : "";
        return (
          <div
            key={`${gone ? "gone:" : ""}${m.id}`}
            className={`kw-mt-r kw-calm${move}`}
            onClick={gone ? undefined : () => store.go(`member:${m.id}`)}
            onAnimationEnd={(e) => {
              if (move && e.target === e.currentTarget) motion.settle(m.id);
            }}
          >
            <Tile lead={{ tile: LeadTile.Node, id: `member:${m.id}` }} />
            <span className="kw-who">
              <b>
                {m.name ?? m.email}
                {m.isYou && <span className="kw-me-tag">{t("ui.you")}</span>}
              </b>
              <span>{m.email}</span>
            </span>
            <span className="kw-role">{t(`role.${m.role}`)}</span>
            <Mark level={st.level} words={st.text} />
            <Mark level={tf.level} words={tf.text} />
            <span className={`kw-all${m.accessAll ? "" : " kw-no"}`}>{t(m.accessAll ? "ui.accessAll" : "ui.accessAssigned")}</span>
          </div>
        );
      })}
    </>
  );
}

function BlockView({ b }: { b: Block }) {
  const run = useAct();
  const { report } = useCore();
  if ("setting" in b) return <SettingRowView setting={b.setting} report={report} />;
  if ("secret" in b) return <SecretField b={b} />;
  if ("totp" in b)
    return (
      <div className="kw-f">
        <span className="kw-k">{t("field.totp")}</span>
        <span className="kw-v">
          <TotpCode itemId={b.totp} />
        </span>
        <span className="kw-fa">{b.verb && <ActIconButton icon="copy" tip={copyTip()} act={{ verb: b.verb }} />}</span>
      </div>
    );
  if ("field" in b)
    return (
      <div className="kw-f">
        <span className="kw-k">{say(b.field)}</span>
        <span className="kw-v">
          {say(b.value) !== "" && <span className={b.mono ? "kw-mono" : b.dim ? "kw-dim" : undefined}>{say(b.value)}</span>}
          {b.faint && <span className="kw-faint">{say(b.faint)}</span>}
          {b.mark && <Mark level={b.mark.level} words={b.mark.text} />}
        </span>
        <span className="kw-fa">
          {b.copy && <ActIconButton icon="copy" tip={copyTip()} act={b.copy as Act} />}
          {b.open && <IconButton icon="ext" tip={t("ui.open")} />}
        </span>
      </div>
    );
  if ("ref" in b) return <RefView b={b} />;
  if ("sig" in b) return <SigView b={b} />;
  if ("marks" in b)
    return (
      <div className="kw-marks">
        {b.marks.map((m, i) => (
          <Mark key={i} level={m.level} words={m.text} />
        ))}
      </div>
    );
  if ("members" in b) return <MembersTable members={b.members} />;
  if ("skeleton" in b) return <BlockSkeleton kind={b.skeleton} rows={b.rows} words={b.words} />;
  if ("mapdoor" in b)
    return (
      <div className="kw-mapdoor" onClick={() => run({ map: b.mapdoor })}>
        <span className="kw-ic">
          <Icon name="map" />
        </span>
        <span className="kw-tx">
          <b>{say(b.title)}</b>
          <span>{say(b.sub)}</span>
        </span>
        <button type="button" className="kw-btn kw-quiet">
          <Icon name="map" />
          {t("ui.openMap")}
        </button>
      </div>
    );
  return <p className="kw-para">{say(b.para)}</p>;
}

export function DocumentView({ doc }: { doc: DocSpec }) {
  return (
    <>
      <HeroView hero={doc.hero} />
      {doc.sections.map((s, i) => (
        <SectionView key={i} s={s} />
      ))}
      {doc.note && (
        <p className="kw-note">
          <Icon name="info" />
          <span>{say(doc.note)}</span>
        </p>
      )}
      {doc.history && (
        <div className="kw-hist">
          <Icon name="clock" />
          <span>{say(doc.history)}</span>
        </div>
      )}
    </>
  );
}
