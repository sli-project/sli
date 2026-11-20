// @vitest-environment jsdom
import * as React from "react";
import { afterEach, expect, it, vi } from "vitest";
import { createScope } from "./scope";
import { UI_API, type PluginUiDescriptor } from "./contract";

const descriptor: PluginUiDescriptor = { plugin_id: "sli.remote-access", ui_api: UI_API, version: "1.0.0",
  routes: ["/extensions/sli.remote-access/accounts"], entry: { path: "entry.js", sha256: "a".repeat(64) }, required_capabilities: [] };
const scopes: ReturnType<typeof createScope>[] = [];
function scope(item = descriptor, session = "session-1") {
  const value = createScope(item, session, document.createElement("div"), vi.fn(), vi.fn(), vi.fn());
  scopes.push(value);
  return value;
}
afterEach(() => { scopes.splice(0).forEach((value) => value.dispose()); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

it("shares React and exposes immutable public primitives", () => {
  const { api } = scope();
  expect(api.react.createElement).toBe(React.createElement);
  expect(api.react.useState).toBe(React.useState);
  expect(Object.isFrozen(api)).toBe(true);
  expect(Object.isFrozen(api.react)).toBe(true);
  expect("queryClient" in api).toBe(false);
  expect("bootstrap" in api).toBe(false);
});

it.each(["../core", "/api/core", "https://example.invalid/api", "//example.invalid/api", "%2e%2e/core", "rows/../../core", "rows\\core", "rows#fragment"])("blocks HTTP escape %s before fetch", async (path) => {
  const fetcher = vi.fn();
  vi.stubGlobal("fetch", fetcher);
  await expect(scope().api.http.get(path)).rejects.toMatchObject({ code: "invalid" });
  expect(fetcher).not.toHaveBeenCalled();
});

it("pins HTTP to the plugin prefix and aborts pending reads on unmount", async () => {
  const fetcher = vi.fn().mockImplementation(async (url: string) => new Response(
    url.endsWith("/descriptor") ? JSON.stringify(descriptor) : '{"items":[]}'));
  vi.stubGlobal("fetch", fetcher);
  const owned = scope();
  await expect(owned.api.http.get("rows?limit=1")).resolves.toEqual({ items: [] });
  const [url, options] = fetcher.mock.calls[1];
  expect(url).toBe("/api/plugins/sli.remote-access/rows?limit=1");
  expect(options.signal.aborted).toBe(false);
  owned.dispose();
  expect(options.signal.aborted).toBe(true);
  await expect(owned.api.http.get("rows")).rejects.toMatchObject({ code: "unavailable" });
});

it.each(["before", "during"])("rejects API data if the plugin version changes %s a request", async (when) => {
  let calls = 0;
  const changed = { ...descriptor, version: "1.1.0" };
  const fetcher = vi.fn().mockImplementation(async (url: string) => {
    if (!url.endsWith("/descriptor")) return new Response('{"items":["new-data"]}');
    return new Response(JSON.stringify(when === "before" || calls++ > 0 ? changed : descriptor));
  });
  vi.stubGlobal("fetch", fetcher);
  const fail = vi.fn();
  const owned = createScope(descriptor, "session-1", document.createElement("div"), vi.fn(), fail, vi.fn());
  scopes.push(owned);
  await expect(owned.api.http.get("rows")).rejects.toMatchObject({ code: "version" });
  expect(fail).toHaveBeenCalledWith(expect.objectContaining({ code: "version" }));
  if (when === "before") expect(fetcher).toHaveBeenCalledTimes(1);
});

it("only navigates to declared plugin routes and only renders in its container", () => {
  const owned = scope();
  expect(owned.api.navigation.href(descriptor.routes[0])).toBe(`/app${descriptor.routes[0]}`);
  expect(() => owned.api.navigation.go("/settings")).toThrow("invalid");
  expect(() => owned.api.render(document.body, null)).toThrow("invalid");
});

it("isolates cache hashes by plugin, asset version, and rights/session", async () => {
  const first = scope();
  const second = scope({ ...descriptor, plugin_id: "sli.fixture" });
  const updated = scope({ ...descriptor, version: "2.0.0" });
  const rights = scope(descriptor, "session-2");
  for (const owned of [first, second, updated, rights]) await owned.api.cache.query(["rows"], async () => 1);
  const hashes = [first, second, updated, rights].map((owned) => owned.client.getQueryCache().getAll()[0].queryHash);
  expect(new Set(hashes).size).toBe(4);
  expect(first.client.getQueryCache().getAll()[0].queryKey).toEqual(["plugin-ui", descriptor.plugin_id, descriptor.version, descriptor.entry.sha256, "session-1", "rows"]);
  first.dispose();
  expect(first.client.getQueryCache().getAll()).toHaveLength(0);
  expect(second.client.getQueryCache().getAll()).toHaveLength(1);
});

it("aborts in-flight queries and clears listeners/timers despite a broken cleanup", async () => {
  vi.useFakeTimers();
  try {
    const owned = scope();
    const listener = vi.fn();
    const timer = vi.fn();
    owned.api.resources.listen(window, "plugin-fixture", listener);
    owned.api.resources.interval(timer, 100);
    owned.api.resources.timeout(timer, 100);
    owned.api.resources.cleanup(() => { throw new Error("fixture cleanup failure"); });
    const query = { signal: undefined as AbortSignal | undefined };
    const pending = owned.api.cache.query(["pending"], (signal) => { query.signal = signal; return new Promise(() => {}); }).catch(() => undefined);
    expect(owned.dispose()).toEqual({ listeners: 0, timers: 0, queries: 0, errors: 1 });
    expect(query.signal?.aborted).toBe(true);
    window.dispatchEvent(new Event("plugin-fixture"));
    vi.advanceTimersByTime(1000);
    expect(listener).not.toHaveBeenCalled();
    expect(timer).not.toHaveBeenCalled();
    await pending;
  } finally { vi.useRealTimers(); }
});
