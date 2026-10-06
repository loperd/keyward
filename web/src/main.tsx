// The web app's page: the shared window over the tab's own backend, for the
// one server this app is deployed in front of.
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "@keyward/core";
import { WebBackend } from "./backend";

// Behind the dev server's proxy the page's own origin is the server.
const backend = new WebBackend(__KEYWARD_PROXIED__ ? { server: location.origin } : {});

const root = document.getElementById("root");
if (!root) throw new Error("index.html has no #root");
createRoot(root).render(
  <StrictMode>
    <App backend={backend} />
  </StrictMode>,
);
