// What stands while something is on its way. Nothing is ever an empty
// screen: the window, a document, a table, a code or a map each has a
// skeleton in the shape of what is coming, swept by one shared shimmer, and
// a wait that has words says them on a status line with a running bar.
//
// The boot screen (Loading) is the window's own skeleton — the strip with its
// traffic lights' blank and a turning mark on the vault's crumb, two list
// columns, the inspector with a hero and fields — and it continues the static
// splash in the page's HTML (ui/core/src/ui/splash.css). The skeletons inside
// a sheet come up only after --dur-fast, so an answer that is there at once
// never flickers; the content that replaces them fades in.
import { WindowButtons } from "./WindowButtons";
import { t, text, type Key, type Text } from "../i18n";
import { SkeletonKind } from "../doc/spec";
import "./loading.css";

/// What the app is waiting for while the window is not up yet: the
/// session's answer, the catalogue, then the plugins' places.
export enum LoadPhase {
  Session = "session",
  Catalog = "catalog",
  Places = "places",
}

const PHASE_WORDS: Record<LoadPhase, Key> = {
  [LoadPhase.Session]: "load.session",
  [LoadPhase.Catalog]: "load.catalog",
  [LoadPhase.Places]: "load.places",
};

/// The words of a phase, in the language of the moment.
export const phaseWords = (p: LoadPhase): string => t(PHASE_WORDS[p]);


/// One bar of a skeleton. Its width comes from its place (loading.css), so
/// rows differ the way real names do and every drawing is the same.
function Bar({ k }: { k: string }) {
  return <span className={`sk sk-${k}`} aria-hidden="true" />;
}

/// A loader that does not know how long it waits: a ring that turns, the
/// size of an icon.
export function Turning({ className = "" }: { className?: string }) {
  return (
    <svg className={`icon load-ring ${className}`} viewBox="0 0 16 16" aria-hidden="true">
      <circle className="load-ring-bg" cx="8" cy="8" r="5.5" />
      <circle className="load-ring-fg" cx="8" cy="8" r="5.5" />
    </svg>
  );
}

/// A wait said in words where the eye is: a turning mark in a soft circle,
/// the words, and a running bar under them. `quiet`: it comes up only after
/// --dur-fast (inside a sheet); the boot screen's is there at once.
export function Pending({ words, quiet = true }: { words: string; quiet?: boolean }) {
  return (
    <div className={`load-status${quiet ? " sk-late" : ""}`} role="status" aria-live="polite">
      <span className="load-pulse" aria-hidden="true">
        <Turning />
      </span>
      <span className="load-words" key={words}>
        {words}
      </span>
      <span className="load-bar" aria-hidden="true" />
    </div>
  );
}

/// The hero of a document still on its way: the 48px tile, the title, the
/// place, the state, the main action and two more.
export function HeroSkeleton() {
  return (
    <header className="hero sk-hero" aria-hidden="true">
      <Bar k="hero-tile" />
      <div className="hero-t">
        <span className="sk-line sk-l"><Bar k="title" /></span>
        <span className="sk-line"><Bar k="place" /></span>
        <span className="sk-line sk-state"><Bar k="state" /></span>
        <span className="acts">
          <Bar k="button" />
          <Bar k="icon" />
          <Bar k="icon" />
        </span>
      </div>
    </header>
  );
}

/// Fields on their way: the document's label column, then a value.
export function FieldsSkeleton({ rows }: { rows: number }) {
  return (
    <div className="sk-fields" aria-hidden="true">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="f sk-f">
          <span className="k"><Bar k="label" /></span>
          <span className="v"><Bar k="value" /></span>
          <span />
        </div>
      ))}
    </div>
  );
}

/// The members table on its way: its real heads, then rows of bars in its
/// columns.
export function MembersSkeleton({ rows }: { rows: number }) {
  return (
    <div className="sk-members">
      <div className="mt-h">
        <span />
        <span>{t("ui.th.name")}</span>
        <span>{t("ui.th.role")}</span>
        <span>{t("ui.th.status")}</span>
        <span>{t("ui.th.tfa")}</span>
        <span>{t("ui.th.access")}</span>
      </div>
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="mt-r sk-mt" aria-hidden="true">
          <Bar k="tile-round" />
          <span className="sk-two">
            <Bar k="name" />
            <Bar k="sub" />
          </span>
          <Bar k="role" />
          <Bar k="mark" />
          <Bar k="mark" />
          <Bar k="access" />
        </div>
      ))}
    </div>
  );
}

/// A skeleton block of a document, with its words when the wait has any.
export function BlockSkeleton({ kind, rows, words }: { kind: SkeletonKind; rows: number; words?: Text | undefined }) {
  return (
    <div className={`sk-block sk-late sk-${kind}-block`}>
      {kind === SkeletonKind.Members ? <MembersSkeleton rows={rows} /> : <FieldsSkeleton rows={rows} />}
      {words && <Pending words={text(words)} quiet={false} />}
    </div>
  );
}

/// A whole document on its way (an edit opened before its item came): the
/// hero, then a section of fields.
export function DocSkeleton({ rows = 3, words }: { rows?: number; words?: string }) {
  return (
    <div className="sk-doc sk-late">
      <HeroSkeleton />
      <section className="sec" aria-hidden="true">
        <div className="sec-h"><Bar k="head" /></div>
        <FieldsSkeleton rows={rows} />
      </section>
      {words && <Pending words={words} quiet={false} />}
    </div>
  );
}

/// A list column's rows on their way: a caption, then two-line rows (a tile,
/// a name, a line under it).
function ColumnSkeleton({ rows, tier }: { rows: number; tier: number }) {
  return (
    <section className={`col sk-col sk-tier-${tier}`} aria-hidden="true">
      <div className="list">
        <div className="grp"><Bar k="caption" /></div>
        {Array.from({ length: rows }, (_, i) => (
          <div key={i} className="sk-row">
            <Bar k="tile" />
            <span className="sk-two">
              <Bar k="name" />
              <Bar k="sub" />
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}

/// The boot screen: the window's skeleton while the session, the catalogue
/// and the plugins' places are on their way. `leaving`: what it waited for
/// has come; it fades out over it at --dur and is gone (`onGone`).
export function Loading({ phase, leaving = false, onGone }: { phase: LoadPhase; leaving?: boolean; onGone?: () => void }) {
  return (
    <div
      className={`window loading${leaving ? " leaving" : ""}`}
      aria-busy={!leaving}
      inert={leaving}
      onAnimationEnd={(e) => {
        if (leaving && e.target === e.currentTarget) onGone?.();
      }}
    >
      <header className="strip" data-tauri-drag-region="deep">
        <WindowButtons />
        <div className="nav" aria-hidden="true">
          <Bar k="ctl" />
          <Bar k="ctl" />
        </div>
        <div className="qline sk-qline">
          <span className="crumbs">
            <span className="crumb last">
              <Turning className="load-crumb-mark" />
              <span>{t("root")}</span>
            </span>
          </span>
        </div>
        <span className="sk-tools" aria-hidden="true">
          <Bar k="ctl" />
          <Bar k="ctl" />
          <Bar k="ctl" />
          <Bar k="ava" />
        </span>
      </header>
      <main className="stage">
        <div className="cols">
          <ColumnSkeleton rows={8} tier={0} />
          <ColumnSkeleton rows={6} tier={1} />
        </div>
        <section className="insp">
          <div className="doc">
            <HeroSkeleton />
            <section className="sec" aria-hidden="true">
              <div className="sec-h"><Bar k="head" /></div>
              <FieldsSkeleton rows={2} />
            </section>
            <Pending words={phaseWords(phase)} quiet={false} />
          </div>
        </section>
      </main>
    </div>
  );
}
