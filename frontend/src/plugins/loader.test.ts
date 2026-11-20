// @vitest-environment node
import { afterEach, expect, it, vi } from "vitest";
import { UI_API, type PluginUiDescriptor } from "./contract";
import { loadDescriptor, loadModule, PluginUiError, validateDescriptor } from "./loader";

const bytes = new TextEncoder().encode("export function createPlugin() {}");
const digest = await crypto.subtle.digest("SHA-256", bytes);
const sha256 = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
const descriptor: PluginUiDescriptor = {
  plugin_id: "sli.remote-access", ui_api: UI_API, version: "1.0.0",
  routes: ["/extensions/sli.remote-access/accounts"],
  entry: { path: "entry.js", sha256 },
  required_capabilities: ["reports.catalog"],
};
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it.each(["../entry.js", "/entry.js", "https://example.invalid/entry.js", "//example.invalid/entry.js", "assets/%2e%2e/entry.js", "assets\\entry.js"])("rejects non-local entry %s", (path) => {
  expect(() => validateDescriptor({ ...descriptor, entry: { ...descriptor.entry, path } }, descriptor.plugin_id)).toThrow(PluginUiError);
});

it("rejects unknown UI API and routes outside the plugin namespace", () => {
  expect(() => validateDescriptor({ ...descriptor, ui_api: "future" }, descriptor.plugin_id)).toThrow("unsupported");
  expect(() => validateDescriptor({ ...descriptor, routes: ["/settings"] }, descriptor.plugin_id)).toThrow("invalid");
  expect(() => validateDescriptor(descriptor, "../sli.remote-access")).toThrow("invalid");
  expect(() => validateDescriptor({ ...descriptor, routes: [descriptor.routes[0], descriptor.routes[0]] }, descriptor.plugin_id)).toThrow("invalid");
});

it("verifies bytes before importing the content-addressed local module", async () => {
  const fetcher = vi.fn().mockResolvedValue(new Response(bytes, { headers: { "Content-Type": "application/javascript; charset=utf-8" } }));
  vi.stubGlobal("fetch", fetcher);
  const module = { createPlugin: vi.fn() };
  const importer = vi.fn().mockResolvedValue(module);
  const signal = new AbortController().signal;
  expect(await loadModule(descriptor, signal, importer)).toBe(module);
  const path = `/api/v1/ui/plugins/sli.remote-access/assets/${descriptor.entry.sha256}/entry.js`;
  expect(fetcher).toHaveBeenCalledWith(path, { signal, credentials: "same-origin", redirect: "error", cache: "no-store" });
  expect(importer).toHaveBeenCalledWith(path);
});

it("does not execute a module whose bytes differ from its descriptor", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("changed", { headers: { "Content-Type": "application/javascript" } })));
  const importer = vi.fn();
  await expect(loadModule(descriptor, new AbortController().signal, importer)).rejects.toMatchObject({ code: "integrity" });
  expect(importer).not.toHaveBeenCalled();
});

it.each([401, 403, 409, 503])("preserves honest denial/integrity/unavailable states (%s)", async (status) => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: status === 409 ? "plugin_ui_integrity_failed" : "error" }), { status })));
  await expect(loadDescriptor(descriptor.plugin_id, new AbortController().signal)).rejects.toMatchObject({ code: status < 409 ? "denied" : status === 409 ? "integrity" : "unavailable" });
});

it("stops after verification when the route has been unmounted", async () => {
  const controller = new AbortController();
  vi.stubGlobal("fetch", vi.fn().mockImplementation(() => { controller.abort(); return Promise.resolve(new Response(bytes, { headers: { "Content-Type": "application/javascript" } })); }));
  const importer = vi.fn();
  await expect(loadModule(descriptor, controller.signal, importer)).rejects.toBeDefined();
  expect(importer).not.toHaveBeenCalled();
});

it("asks for a reload when the server fences the UI during plugin activation", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: "plugin_ui_updating" }), { status: 503 })));
  await expect(loadDescriptor(descriptor.plugin_id, new AbortController().signal)).rejects.toMatchObject({ code: "version" });
});
