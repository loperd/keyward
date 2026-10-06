// What the build hands the app: the one server it is deployed for.
interface ImportMetaEnv {
  readonly VITE_KEYWARD_SERVER?: string;
}
interface ImportMeta {
  readonly env: ImportMetaEnv;
}
/// Set by vite.config.ts: the dev server proxies the server's API.
declare const __KEYWARD_PROXIED__: boolean;
