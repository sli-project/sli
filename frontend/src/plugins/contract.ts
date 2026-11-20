import type * as React from "react";
import type { Locale, MessageKey } from "../i18n";
import type { ResultState } from "../design-system/StateView";

export const UI_API = "sli.plugin-ui.v1";
export type PluginUiDescriptor = {
  plugin_id: string;
  ui_api: typeof UI_API;
  version: string;
  routes: string[];
  entry: { path: string; sha256: string };
  required_capabilities: string[];
};

/** Public primitives only. Installed code is trusted, not a same-realm sandbox.
 * Plugins use these resources rather than global listeners/timers or private
 * imports. Each factory owns one mount, even when ESM is cached by the browser.
 */
export type PluginHostApi = Readonly<{
  ui_api: typeof UI_API;
  react: Pick<typeof React, "createElement" | "Fragment" | "useState" | "useEffect" | "useMemo" | "useRef">;
  render: (container: HTMLElement, node: React.ReactNode) => void;
  http: { get: <T>(path: string) => Promise<T> };
  i18n: { locale: Locale; t: (key: MessageKey, params?: Record<string, string | number>) => string };
  theme: { text: string; surface: string; spacing: string };
  navigation: { href: (route: string) => string; go: (route: string) => void };
  ReportState: React.ComponentType<{ state: ResultState; detail?: React.ReactNode }>;
  /** An optional, host-approved page adapter. No arbitrary report identifiers. */
  Page?: React.ComponentType;
  resources: {
    listen: (target: EventTarget, event: string, callback: EventListener) => () => void;
    timeout: (callback: () => void, delay: number) => () => void;
    interval: (callback: () => void, delay: number) => () => void;
    cleanup: (callback: () => void) => () => void;
  };
  cache: { query: <T>(key: readonly string[], load: (signal: AbortSignal) => Promise<T>) => Promise<T> };
}>;

export type PluginUiInstance = {
  mount: (container: HTMLElement, api: PluginHostApi) => void;
  unmount: () => void;
};
export type PluginUiModule = { createPlugin: () => PluginUiInstance };
