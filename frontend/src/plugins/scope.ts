import * as React from "react";
import { hashKey, QueryClient } from "@tanstack/react-query";
import { StateView } from "../design-system/StateView";
import { getLocale, t } from "../i18n";
import { type PluginHostApi, type PluginUiDescriptor, UI_API } from "./contract";
import { loadDescriptor, localResponse, PluginUiError, sameVersion } from "./loader";

export type CleanupResult = { listeners: number; timers: number; queries: number; errors: number };

export function createScope(descriptor: PluginUiDescriptor, sessionKey: string, container: HTMLElement,
  render: (node: React.ReactNode) => void, fail: (error?: PluginUiError) => void, go: (href: string) => void, Page?: React.ComponentType) {
  const namespace = ["plugin-ui", descriptor.plugin_id, descriptor.version, descriptor.entry.sha256, sessionKey];
  // Page adapters also run in a per-mount cache. Their existing query hashes
  // are scoped without changing the core report renderer's contracts.
  const client = new QueryClient({ defaultOptions: { queries: {
    retry: false, queryKeyHashFn: (key) => hashKey([...namespace, ...key]),
  } } });
  const controller = new AbortController();
  const cleanups = new Set<() => void>();
  let active = true;
  let listeners = 0;
  let timers = 0;
  let errors = 0;
  const assertActive = () => { if (!active) throw new PluginUiError("unavailable"); };
  const cleanup = (callback: () => void) => {
    assertActive();
    const once = () => { if (cleanups.delete(once)) callback(); };
    cleanups.add(once);
    return once;
  };
  const guarded = (callback: () => void) => { if (active) { try { callback(); } catch { fail(); } } };
  const href = (route: string) => {
    assertActive();
    if (!descriptor.routes.includes(route)) throw new PluginUiError("invalid");
    return `/app${route}`;
  };
  const resources = Object.freeze({
    cleanup,
    listen: (target: EventTarget, event: string, callback: EventListener) => {
      assertActive();
      const listener: EventListener = (value) => guarded(() => callback(value));
      target.addEventListener(event, listener);
      listeners++;
      return cleanup(() => { target.removeEventListener(event, listener); listeners--; });
    },
    timeout: (callback: () => void, delay: number) => {
      assertActive();
      let cancel: () => void;
      const timer = window.setTimeout(() => { cancel(); guarded(callback); }, delay);
      timers++;
      cancel = cleanup(() => { window.clearTimeout(timer); timers--; });
      return cancel;
    },
    interval: (callback: () => void, delay: number) => {
      assertActive();
      const timer = window.setInterval(() => guarded(callback), delay);
      timers++;
      return cleanup(() => { window.clearInterval(timer); timers--; });
    },
  });
  const api: PluginHostApi = Object.freeze({
    ui_api: UI_API,
    react: Object.freeze({ createElement: React.createElement, Fragment: React.Fragment,
      useState: React.useState, useEffect: React.useEffect, useMemo: React.useMemo, useRef: React.useRef }),
    render: (target: HTMLElement, node: React.ReactNode) => {
      assertActive();
      if (target !== container) throw new PluginUiError("invalid");
      render(node);
    },
    http: Object.freeze({ get: async <T,>(path: string): Promise<T> => {
      assertActive();
      // Accept a relative, canonical path only; no scheme, encoded path,
      // traversal, backslashes, fragment, or caller-controlled fetch options.
      const [pathname] = path.split("?");
      if (!/^[a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_.-]+)*$/.test(pathname)
        || pathname.split("/").some((part) => part === "." || part === "..") || /[\\#\u0000-\u0020]/.test(path)) throw new PluginUiError("invalid");
      const url = `/api/plugins/${descriptor.plugin_id}/${path}`;
      const check = async () => {
        const next = await loadDescriptor(descriptor.plugin_id, controller.signal);
        if (!sameVersion(descriptor, next)) {
          const error = new PluginUiError("version");
          fail(error);
          throw error;
        }
        assertActive();
      };
      await check();
      const result = await (await localResponse(url, controller.signal)).json() as T;
      // Discard a response if activation raced the request.
      await check();
      return result;
    } }),
    i18n: Object.freeze({ locale: getLocale(), t }),
    theme: Object.freeze({ text: "var(--sli-text)", surface: "var(--sli-surface-1)", spacing: "var(--sli-space-3)" }),
    navigation: Object.freeze({ href, go: (route: string) => go(href(route)) }),
    ReportState: StateView,
    Page,
    resources,
    cache: Object.freeze({ query: <T,>(key: readonly string[], load: (signal: AbortSignal) => Promise<T>) => {
      assertActive();
      return client.fetchQuery({ queryKey: [...namespace, ...key], queryFn: ({ signal }) => load(signal) });
    } }),
  });
  return { api, client, dispose: (): CleanupResult => {
    if (active) {
      active = false;
      controller.abort();
      for (const callback of [...cleanups]) { try { callback(); } catch { errors++; } }
      // cancelQueries aborts query signals synchronously; clear prevents late
      // resolutions from repopulating a cache owned by an unmounted plugin.
      void client.cancelQueries();
      client.clear();
    }
    return { listeners, timers, queries: client.getQueryCache().getAll().length, errors };
  } };
}
