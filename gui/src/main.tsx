import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { installActionLog } from "./actionLog";
import { invoke as realInvoke } from "@tauri-real/core";
import "./styles.css";

installActionLog((cmd, args) => realInvoke(cmd, args as Record<string, unknown>));

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
