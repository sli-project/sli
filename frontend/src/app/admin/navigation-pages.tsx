import { createRoute, Link, type AnyRootRoute } from "@tanstack/react-router";
import declarations from "../../../../config/navigation_v3.json";
import type { NavigationEntryDto } from "../../api/report-v2-types";
import { PageHeader, StateView } from "../../design-system";
import { t, type MessageKey } from "../../i18n";
import { useEffectiveAccess } from "../App";
import { AccessRequestStateView, useAccessRequest } from "../access-request-state";
import { navigationEntryAllowed, type NavAccess } from "../navigation";
import { PluginPage } from "./plugin-page";
import { SystemStatusPage } from "./status";

const adminEntries = declarations.sections.find((section) => section.id === "admin")!.groups.flatMap<NavigationEntryDto>((group) => group.entries);
export const adminPlaceholderEntries = adminEntries.filter((entry) => entry.path.startsWith("/admin/"));

const legacyEntries: Array<NavigationEntryDto & { parent: string }> = [
  { id: "setup", label: "shell.nav.setup", path: "/setup", icon: "check", capabilities: ["access.manage"], parent: "/admin/status" },
  { id: "project-readiness", label: "shell.nav.project-readiness", path: "/project-readiness", icon: "layers", reports: ["operations.readiness"], parent: "/admin/status" },
  { id: "platform-settings", label: "shell.nav.platform-settings", path: "/platform-settings", icon: "settings", capabilities: ["access.manage"], reports: ["decoys.registry", "watch.registry"], parent: "/admin/status" },
  { id: "access-requests", label: "shell.nav.access-requests", path: "/access-requests", icon: "key", capabilities: ["access.manage"], parent: "/access" },
  { id: "local-accounts", label: "access.admin.title", path: "/admin", icon: "users", capabilities: ["access.manage"], parent: "/access" },
  { id: "session-settings", label: "shell.adminNav.locale", path: "/settings", icon: "settings", capabilities: ["access.manage"], parent: "/admin/language-time" },
];

/** Prefer a page's own menu entry before falling back to its related destination. */
export function adminNavigationPath(pathname: string): string {
  if (adminEntries.some((entry) => entry.path === pathname)) return pathname;
  return legacyEntries.find((entry) => entry.path === pathname)?.parent ?? pathname;
}

export function AdminRelatedLinks({ pathname, access }: { pathname: string; access: NavAccess }) {
  const parent = legacyEntries.find((entry) => entry.path === pathname)?.parent ?? pathname;
  if (parent === "/access") return null;
  const links = legacyEntries.filter((entry) => entry.parent === parent && entry.path !== pathname && navigationEntryAllowed(entry, access));
  if (!links.length) return null;
  return <details className="sli-ds-filters__additional">
    <summary>{t("shell.adminNav.related")}</summary>
    <ul className="sli-ds-link-list">{links.map((entry) => <li key={entry.id}><Link to={entry.path}>{t(entry.label as MessageKey)}</Link></li>)}</ul>
  </details>;
}

function AdminPlaceholderPage({ entry }: { entry: NavigationEntryDto }) {
  const access = useEffectiveAccess();
  const request = useAccessRequest();
  const title = t(entry.label as MessageKey);
  let content;
  if (!access || request?.error) content = <AccessRequestStateView/>;
  else if (!navigationEntryAllowed(entry, {
    capabilities: new Set(access.capabilities),
    reports: new Set(access.reports.filter((report) => report.allowed).map((report) => report.report_key)),
  })) content = <StateView state="denied"/>;
  else if (entry.path.startsWith("/admin/plugins/")) return <PluginPage key={entry.id} pluginId={entry.path.slice("/admin/plugins/".length)} title={title}/>;
  else if (entry.path === "/admin/status") return <SystemStatusPage/>;
  else content = <p className="sli-ds-muted">{t("shell.adminNav.development")}</p>;
  return <section className="sli-ds-report"><PageHeader title={title}/>{content}</section>;
}

export function createAdminPlaceholderRoutes(parent: AnyRootRoute) {
  return adminPlaceholderEntries.map((entry) => createRoute({
    getParentRoute: () => parent, path: entry.path, component: () => <AdminPlaceholderPage entry={entry}/>,
  }));
}
