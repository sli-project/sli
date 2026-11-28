/**
 * Navigation comes from the core registry. It is a convenience, never
 * authorization: pages and the server still enforce their existing grants.
 */
import type { NavigationEntryDto, NavigationRegistryDto } from "../api/report-v2-types";
import declarations from "../../../config/navigation_v3.json";
import { defaultParseSearch, defaultStringifySearch, redirect } from "@tanstack/react-router";
import { t, type MessageKey } from "../i18n";

export type NavLink = { id: string; label: string; path: string; icon: string };
export type NavGroup = { id: string; title: string; items: NavLink[] };
export type NavSection = { id: string; title: string; groups: NavGroup[] };
export type NavAccess = {
  /** report_key values the server marked as allowed for this user */
  reports: ReadonlySet<string>;
  capabilities: ReadonlySet<string>;
};

const betaOrder = new Map(declarations.beta_entries.map((id, index) => [id, index]));
const previewOrder = new Map(declarations.preview_entries.map((id, index) => [id, betaOrder.size + index]));
const entries = declarations.sections.flatMap((section) => section.groups.flatMap<NavigationEntryDto>((group) => group.entries));
const betaEntries = entries.filter((entry) => betaOrder.has(entry.id));
const betaReportPaths = new Set(betaEntries.flatMap((entry) => [entry.path, ...(entry.views?.map((view) => view.path) ?? [])]));
const betaPlugins = new Set(betaEntries.flatMap((entry) => entry.plugin_id ? [entry.plugin_id] : []));

export function previewModulePath(path: string): boolean {
  const plugin = /^\/(?:admin\/plugins|extensions)\/([^/]+)/.exec(path);
  if (plugin) return declarations.preview_plugins.includes(plugin[1]);
  return /^\/reports?\/(?:workstations|vpn|sigma)\./.test(path)
    && !betaReportPaths.has(path.replace(/^\/reports\//, "/report/").replace(/\/+$/, ""));
}

function outsideBeta(path: string): boolean {
  if (["/cases", "/report-management", "/report-editor", "/report-builder"].some((alias) => isActivePath(alias, path))) return true;
  const plugin = /^\/(?:admin\/plugins|extensions)\/([^/]+)/.exec(path);
  if (plugin) return !betaPlugins.has(plugin[1]) && !betaEntries.some((entry) => isActivePath(entry.path, path));
  if (/^\/reports?\//.test(path)) return !betaReportPaths.has(path.replace(/^\/reports\//, "/report/"));
  return entries.some((entry) => !betaOrder.has(entry.id) && isActivePath(entry.path, path));
}

export function navigationEntryAllowed(entry: NavigationEntryDto, access: NavAccess): boolean {
  return Boolean(entry.always || entry.reports?.some((key) => access.reports.has(key))
    || entry.capabilities?.some((key) => access.capabilities.has(key)));
}

/** Compatibility routes and workspace membership come from the same registry as the menu. */
export function navigationRedirect(path: string, search: Record<string, unknown>) {
  path = path.replace(/\/+$/, "") || "/";
  // This existing admin alias has no report view in the registry.
  if (path === "/access-center") return { to: "/access", search: { ...search }, replace: true as const };
  const rule = declarations.redirects.find((item) => item.from === path);
  const destination = rule?.to ?? path;
  if (!previewModulePath(destination) && outsideBeta(destination)) return { to: "/", search: {}, replace: true as const };
  return rule ? { to: rule.to, search: { ...search, ...("view" in rule ? { nav_view: rule.view } : {}) }, replace: true as const } : null;
}

export function navigationBeforeLoad(location: { pathname: string; search: Record<string, unknown>; hash: string }) {
  const target = navigationRedirect(location.pathname.replace(/^\/app(?=\/)/, ""), location.search);
  if (target) throw redirect({ ...target, search: target.search as never, hash: target.to === "/" ? "" : location.hash });
}

export const objectSearchPath = declarations.global_search.path;
export const journalSearchPath = "/report/events.journal";

export function globalSearchTarget(rawValue: string, currentSearch = "", onHome = false) {
  const source = new URLSearchParams(currentSearch);
  const search: Record<string, string> = {};
  const period = source.get("period");
  const from = source.get("from");
  const to = source.get("to");
  if (period === "custom" && from && to) {
    Object.assign(search, { period, from, to });
    const timeZone = source.get("tz");
    if (timeZone) search.tz = timeZone;
  } else if (period && ["2h", "24h", "7d", "30d", "90d"].includes(period)) search.period = period;
  else if (onHome) search.period = "24h";
  const q = rawValue.trim();
  if (q) search.q = q;
  return { to: journalSearchPath, search };
}

export function parseShellSearch(search: string) {
  const query = defaultParseSearch(search);
  const q = new URLSearchParams(search).get("q");
  return q === null ? query : { ...query, q };
}

export function stringifyShellSearch(search: Record<string, unknown>) {
  const { q, ...rest } = search;
  if (typeof q !== "string") return defaultStringifySearch(search);
  const params = new URLSearchParams({ q });
  const other = defaultStringifySearch(rest);
  return other ? `${other}&${params}` : `?${params}`;
}

export function reportWorkspace(reportKey: string): NavigationEntryDto | undefined {
  return declarations.sections.flatMap((section) => section.groups.flatMap<NavigationEntryDto>((group) => group.entries))
    .find((entry) => entry.path === `/report/${reportKey}` && "views" in entry);
}

export function preserveNavigationView(search: URLSearchParams, currentSearch: string) {
  const view = new URLSearchParams(currentSearch).get("nav_view");
  if (view) search.set("nav_view", view);
  return search;
}

export function buildNavigation(access: NavAccess, registry?: NavigationRegistryDto): NavSection[] {
  if (!registry) return [];
  const enabled = new Set(registry.enabled_plugins);
  const order = (id: string) => betaOrder.get(id) ?? (registry.modules_preview ? previewOrder.get(id) : undefined);
  const destination = (entry: NavigationEntryDto): NavigationEntryDto => {
    if (entry.id === "file-audit" && !access.reports.has("file-audit.overview")) {
      const allowed = entry.views?.find(view => view.reports?.some(key => access.reports.has(key)));
      if (allowed) return { ...entry, path: allowed.path };
    }
    if (entry.path === "/admin/language-time") return { ...entry, path: "/settings" };
    return entry;
  };
  return registry.sections.map((section) => ({
    id: section.id,
    title: t(section.title as MessageKey),
    groups: section.groups.map((group) => ({
      id: group.id,
      title: group.title ? t(group.title as MessageKey) : "",
      items: group.entries.filter((entry) =>
        order(entry.id) !== undefined
        && (entry.path !== "/admin/status" || access.capabilities.has("access.manage")
          || ["operations.readiness", "decoys.registry", "watch.registry"].some((key) => access.reports.has(key)))
        && (!entry.plugin_id || enabled.has(entry.plugin_id)) && navigationEntryAllowed(entry, access)
      ).sort((a, b) => order(a.id)! - order(b.id)!)
        .map(destination).map(({ id, label, path, icon }) => ({ id, label: t(label as MessageKey), path, icon: id === "computers-report" ? "computer" : icon })),
    })).filter((group) => group.items.length > 0)
      .sort((a, b) => order(a.items[0].id)! - order(b.items[0].id)!),
  })).filter((section) => section.groups.length > 0)
    .sort((a, b) => order(a.groups[0].items[0].id)! - order(b.groups[0].items[0].id)!);
}

/** A path is active for its own page and its sub-pages; "/" only matches itself. */
export function isActivePath(itemPath: string, pathname: string): boolean {
  if (itemPath === "/") return pathname === "/";
  if (itemPath.startsWith("/report/file-audit.")) return /^\/reports?\/file-audit\./.test(pathname);
  return pathname === itemPath || pathname.startsWith(`${itemPath}/`);
}
