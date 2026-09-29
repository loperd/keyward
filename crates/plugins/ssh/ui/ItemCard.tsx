import { useEffect, useState } from "react";
import { Alert, Icon } from "@keyward/ui";
import { t } from "@keyward/i18n";
import { call } from "@keyward/plugins/call";
import type { PluginItemCardProps } from "@keyward/plugins/types";
import type { SshKeyEntry } from "./types";
import "./style.css";

/// The ssh plugin's block on an item's card.
///
/// The core's card knows nothing about a route: it hands every plugin that is
/// on the item it is showing, and this one looks for itself. An item that is
/// not an ssh key of ours draws nothing at all.
export function SshItemCard({ detail, entryId, onChanged }: PluginItemCardProps) {
  const [hosts, setHosts] = useState<string | null>(null);

  useEffect(() => {
    if (detail.kind !== "ssh_key") {
      setHosts(null);
      return;
    }
    let alive = true;
    // What an item is bound to is the plugin's own knowledge, and it is asked
    // for it: the card carries no field of ours any more.
    void call<SshKeyEntry[]>("ssh", "keys")
      .then((keys) => {
        if (alive) setHosts(keys.find((k) => k.id === entryId)?.hosts ?? "");
      })
      .catch(() => {
        if (alive) setHosts(null);
      });
    return () => {
      alive = false;
    };
  }, [detail.kind, entryId, detail.custom]);

  if (detail.kind !== "ssh_key" || hosts === null) return null;

  return (
    <section className="pane-card tone-amber">
      <h4 className="block-title">{t("routes.hosts")}</h4>
      <Hosts entryId={entryId} value={hosts} onChanged={onChanged} />
    </section>
  );
}

/// An ssh key's hosts.
///
/// This used to be a separate "Routes" section — an extra link between "here is
/// the key" and "here is where it goes". The binding lives in the key's own
/// item, as it was meant to: the agent reads exactly this field.
function Hosts({
  entryId,
  value,
  onChanged,
}: {
  entryId: string;
  value: string;
  onChanged: () => void;
}) {
  const [adding, setAdding] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const list = value
    .split(",")
    .map((h) => h.trim())
    .filter(Boolean);

  const save = async (next: string[]) => {
    setBusy(true);
    setError(null);
    try {
      // Binding a host is the ssh agent's business: the core knows nothing
      // about it, though the field lies in a vault item.
      await call("ssh", "set_hosts", { entry_id: entryId, hosts: next.join(",") });
      setAdding("");
      onChanged();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="hosts">
      <div className="chips">
        {list.map((h) => (
          <button
            key={h}
            type="button"
            className="chip pick"
            disabled={busy}
            title={t("routes.unbind")}
            onClick={() => void save(list.filter((x) => x !== h))}
          >
            {h}
            <span className="x">×</span>
          </button>
        ))}
      </div>
      <div className="with-inner">
        <input
          value={adding}
          onChange={(e) => setAdding(e.target.value)}
          aria-label={t("routes.addHost")}
          placeholder="git.example.com, admin@10.0.0.5"
          spellCheck={false}
          onKeyDown={(e) => {
            if (e.key === "Enter" && adding.trim()) {
              void save([...list, ...adding.split(",").map((h) => h.trim()).filter(Boolean)]);
            }
          }}
        />
        <button
          type="button"
          className="inner"
          disabled={busy || !adding.trim()}
          aria-label={t("routes.bind")}
          onClick={() => void save([...list, ...adding.split(",").map((h) => h.trim()).filter(Boolean)])}
        >
          <Icon name="plus" size={12} />
        </button>
      </div>
      <span className="hint">{t("routes.hostsHint")}</span>
      {error && <Alert message={error} />}
    </div>
  );
}
