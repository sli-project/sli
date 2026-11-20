import { UI_API, type PluginUiDescriptor, type PluginUiModule } from "./contract";

export class PluginUiError extends Error {
  constructor(public readonly code: "invalid" | "integrity" | "unsupported" | "denied" | "unavailable" | "version") { super(code); }
}

export const sameVersion = (first: PluginUiDescriptor, next: PluginUiDescriptor) =>
  first.version === next.version && first.ui_api === next.ui_api
  && first.entry.path === next.entry.path && first.entry.sha256 === next.entry.sha256;

const pluginIdPattern = /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$/;
const assetPattern = /^[a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_-]+)*\.js$/;
const exactKeys = (value: object, keys: string[]) => Object.keys(value).sort().join() === keys.sort().join();

export function validateDescriptor(value: unknown, pluginId: string): PluginUiDescriptor {
  if (!pluginIdPattern.test(pluginId) || !value || typeof value !== "object") throw new PluginUiError("invalid");
  const item = value as Partial<PluginUiDescriptor>;
  if (item.ui_api !== UI_API) throw new PluginUiError("unsupported");
  if (!exactKeys(item, ["plugin_id", "ui_api", "version", "routes", "entry", "required_capabilities"]) || item.plugin_id !== pluginId
    || typeof item.version !== "string" || !/^\d+\.\d+\.\d+$/.test(item.version)) throw new PluginUiError("invalid");
  const prefix = `/extensions/${pluginId}/`;
  if (!Array.isArray(item.routes) || !item.routes.length || item.routes.length > 32
    || item.routes.some((route) => typeof route !== "string" || !route.startsWith(prefix) || !/^[a-z0-9]+(?:[/-][a-z0-9]+)*$/.test(route.slice(prefix.length)))
    || new Set(item.routes).size !== item.routes.length) throw new PluginUiError("invalid");
  if (!item.entry || typeof item.entry !== "object" || !exactKeys(item.entry, ["path", "sha256"])
    || typeof item.entry.path !== "string" || !assetPattern.test(item.entry.path)
    || typeof item.entry.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(item.entry.sha256)) throw new PluginUiError("invalid");
  if (!Array.isArray(item.required_capabilities) || item.required_capabilities.length > 32
    || item.required_capabilities.some((capability) => typeof capability !== "string" || !/^[a-z][a-z0-9_.-]{0,95}$/.test(capability))
    || new Set(item.required_capabilities).size !== item.required_capabilities.length) throw new PluginUiError("invalid");
  return item as PluginUiDescriptor;
}

export const descriptorUrl = (pluginId: string) => {
  if (!pluginIdPattern.test(pluginId)) throw new PluginUiError("invalid");
  return `/api/v1/ui/plugins/${pluginId}/descriptor`;
};

export async function localResponse(path: string, signal: AbortSignal): Promise<Response> {
  const response = await fetch(path, { signal, credentials: "same-origin", redirect: "error", cache: "no-store" });
  if (response.status === 401 || response.status === 403) throw new PluginUiError("denied");
  if (!response.ok) {
    const error = await response.json().catch(() => null) as { error?: string } | null;
    if (error?.error === "plugin_ui_updating") throw new PluginUiError("version");
    throw new PluginUiError(error?.error === "plugin_ui_integrity_failed" ? "integrity" : "unavailable");
  }
  return response;
}

export async function loadDescriptor(pluginId: string, signal: AbortSignal): Promise<PluginUiDescriptor> {
  return validateDescriptor(await (await localResponse(descriptorUrl(pluginId), signal)).json(), pluginId);
}

export async function loadModule(descriptor: PluginUiDescriptor, signal: AbortSignal,
  importModule: (path: string) => Promise<unknown> = (path) => import(/* @vite-ignore */ path)): Promise<PluginUiModule> {
  validateDescriptor(descriptor, descriptor.plugin_id);
  // The server validates the requested digest on EVERY read and serves the
  // checked bytes directly. This closes the fetch -> native import update race
  // without blob: scripts, eval, globals, or weakening script-src 'self'.
  const path = `/api/v1/ui/plugins/${descriptor.plugin_id}/assets/${descriptor.entry.sha256}/${descriptor.entry.path}`;
  const response = await localResponse(path, signal);
  if (!response.headers.get("Content-Type")?.startsWith("application/javascript")) throw new PluginUiError("invalid");
  const bytes = await response.arrayBuffer();
  if (bytes.byteLength > 4 * 1024 * 1024) throw new PluginUiError("invalid");
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const sha256 = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  if (sha256 !== descriptor.entry.sha256) throw new PluginUiError("integrity");
  signal.throwIfAborted();
  const module = await importModule(path);
  if (!module || typeof module !== "object" || typeof (module as PluginUiModule).createPlugin !== "function") throw new PluginUiError("invalid");
  return module as PluginUiModule;
}
