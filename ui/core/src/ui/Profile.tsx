// The account's profile on the Account page: what the server knows about the
// person, read when the page opens — the email and whether it is verified,
// the name, how the master password is stretched, two-step login, and the
// account key's five words to compare with another client's.
import { faultWords } from "./fault";
import { useEffect, useState } from "react";
import { currentLang, t } from "../i18n";
import { type AccountProfile, KdfKind } from "../settings/types";
import { Mark, useCore } from "./marks";
import { Level } from "../model/types";
import "./extensions.css";

const kdfWords = (p: AccountProfile) =>
  p.kdf.kind === KdfKind.Pbkdf2 ? t("prof.kdfPbkdf2", { n: p.kdf.iterations.toLocaleString(currentLang()) }) : t("prof.kdfArgon", { i: p.kdf.iterations, m: p.kdf.memoryMib, p: p.kdf.parallelism });

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="f">
      <span className="k">{label}</span>
      <span className="v">{children}</span>
      <span className="fa" />
    </div>
  );
}

export function ProfileView({ version }: { version: number }) {
  const { backend } = useCore();
  const [p, setP] = useState<AccountProfile | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
  useEffect(() => {
    if (!backend.profile) return;
    let live = true;
    backend.profile().then(
      (x) => live && (setP(x), setFailed(null)),
      (e: unknown) => live && setFailed(faultWords(e)),
    );
    return () => {
      live = false;
    };
  }, [backend, version]);
  if (failed) return <Mark level={Level.Critical} words={t("prof.failed", { reason: failed })} />;
  if (!p)
    return (
      <div className="set set-wait" role="status" aria-label={t("set.loading")}>
        <span className="set-t">
          <b>{t("set.loading")}</b>
        </span>
      </div>
    );
  return (
    <>
      <Field label={t("prof.email")}>
        <span className="mono">{p.email}</span>
        <Mark level={p.emailVerified ? Level.Healthy : Level.Warning} words={t(p.emailVerified ? "prof.verified" : "prof.unverified")} />
      </Field>
      <Field label={t("prof.name")}>{p.name ? <span>{p.name}</span> : <span className="dim">{t("prof.noName")}</span>}</Field>
      <Field label={t("prof.kdf")}>
        <span>{kdfWords(p)}</span>
      </Field>
      <Field label={t("prof.twoFactor")}>
        <Mark level={p.twoFactor ? Level.Healthy : Level.Warning} words={t(p.twoFactor ? "set.on" : "set.off")} />
      </Field>
      <Field label={t("prof.fingerprint")}>
        <span className="ext-words">
          {p.fingerprint.map((w, i) => (
            <code key={i}>{w}</code>
          ))}
        </span>
      </Field>
      {p.created && (
        <Field label={t("prof.since")}>
          <span>{new Date(p.created).toLocaleDateString(currentLang(), { day: "numeric", month: "long", year: "numeric" })}</span>
        </Field>
      )}
    </>
  );
}
