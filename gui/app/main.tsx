// The desktop app's window: the shared core (ui/core) over the daemon, on
// the one page the Tauri window opens (app.html) — see app/README.md.
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "@keyward/core";
import { invoke as realInvoke } from "@tauri-real/core";
import { installActionLog } from "./actionLog";
import { DaemonBackend } from "./backend";
import { DaemonWrites } from "./writes";

// Every command goes through the log of actions, as in the old window.
installActionLog((cmd, args) => realInvoke(cmd, args as Record<string, unknown>));

const root = document.getElementById("root");
if (!root) throw new Error("app.html has no #root");
const backend = new DaemonBackend();
// Writes tell the window what changed the way a sync does; a change to who
// reaches what has the members read again.
const writes = new DaemonWrites(
  (c) => backend.announce(c),
  () => backend.membersChanged(),
);
createRoot(root).render(
  <StrictMode>
    <App backend={backend} writes={writes} />
  </StrictMode>,
);
