// `@keyward/core/demo`: the demo vault, its backend and its writes — for the
// stand and the tests only. Kept out of the main entry so no production
// bundle (the web app, the desktop window) carries the demo's data.
export { DEMO, DEMO_NOW } from "./demo";
export { DemoBackend, DEMO_PLACES, DEMO_WRONG, demoContributions, type DemoOptions } from "./demo-backend";
export { DemoWrites } from "./demo-writes";
export { synthetic, type SyntheticOptions } from "./bench/synthetic";
export { RecordedPlugins, type PluginRecord } from "./demo-records";
