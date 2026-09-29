import "./style.css";
import { useEffect, useState } from "react";
import { Icon } from "@keyward/ui";
import { t } from "@keyward/i18n";
import { call } from "@keyward/plugins/call";
import { setConnecting, setOpened, useConnecting, useOpened, useRevision } from "./state";
import type { HashicorpLink } from "./types";

/// The section's column: the connected Vaults and a button to connect
/// another.
///
/// The list is here rather than on the screen: one Vault is shown on the
/// right, and repeating the list beside it would mean showing the same thing
/// twice.
export function HashicorpContext() {
  const [links, setLinks] = useState<HashicorpLink[]>([]);
  const opened = useOpened();
  const connecting = useConnecting();
  const revision = useRevision();

  useEffect(() => {
    void call<HashicorpLink[]>("hashicorp", "connections")
      .then(setLinks)
      .catch(() => setLinks([]));
  }, [revision]);

  return (
    <div className="group">
      <h4>{t("hashicorp.connections")}</h4>
      {/* The button above the list: the action people come here for the first
          time must not live under a list of what is already done. */}
      <button type="button" className={`nav add ${connecting ? "busy" : ""}`} onClick={() => setConnecting(!connecting)}>
        <Icon name="plus" size={14} />
        <span className="label">{t("hashicorp.connectMore")}</span>
      </button>
      {links.map((l) => (
        <button
          type="button"
          key={l.entry_id}
          className={`nav ${opened === l.entry_id && !connecting ? "on" : ""}`}
          title={`${l.entry_name || l.addr} · ${l.addr}`}
          onClick={() => {
            setConnecting(false);
            setOpened(l.entry_id);
          }}
        >
          <Icon name="vault" />
          <span className="label">{l.entry_name || l.addr}</span>
        </button>
      ))}
    </div>
  );
}
