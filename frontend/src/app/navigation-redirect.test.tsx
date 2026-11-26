// @vitest-environment jsdom
import { createMemoryHistory, createRootRoute, createRoute, createRouter } from "@tanstack/react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { globalSearchTarget, navigationBeforeLoad, navigationRedirect, preserveNavigationView, previewModulePath } from "./navigation";

beforeEach(() => { vi.spyOn(window, "scrollTo").mockImplementation(() => undefined); });
afterEach(() => { vi.restoreAllMocks(); });

describe("registry compatibility redirects", () => {
  it.each([
    ["/access-center", "/access", undefined],
    ["/objects", "/search", undefined],
    ["/report/notifications.channels", "/notifications", "channels"],
    ["/report/notifications.deliveries", "/notifications", "journal"],
    ["/entities", "/search", undefined],
    ["/report/ad.computer-logons", "/report/ad.computers.v6", "logons"],
    ["/workstations", "/report/workstations.overview", "overview"],
    ["/vpn-connections", "/report/vpn.connections", "connections"],
  ])("redirects %s with its filters and fragment", async (from, to, view) => {
    const root = createRootRoute();
    const route = (path: string) => createRoute({ getParentRoute: () => root, path,
      beforeLoad: ({ location }) => navigationBeforeLoad(location) });
    const router = createRouter({ routeTree: root.addChildren([
      route("/access-center"), route("/access"), route("/objects"), route("/entities"), route("/search"), route("/report/$reportKey"),
      route("/vpn-report"), route("/vpn-connections"), route("/notifications"), route("/workstations"),
    ]), basepath: "/app", history: createMemoryHistory({
      initialEntries: [`/app${from}?domain=7&q=synthetic&tab=details&return_to=%2Fapp%2F#evidence`],
    }) });
    await router.load();
    // History contains the public URL; router state uses paths relative to the basepath.
    await expect.poll(() => router.history.location.pathname).toBe(`/app${to}`);
    expect(router.state.location.search).toMatchObject({ domain: 7, q: "synthetic", tab: "details", return_to: "/app/" });
    expect(router.state.location.search).toMatchObject(view ? { nav_view: view } : {});
    expect(router.state.location.hash).toBe("evidence");
    const publicUrl = new URL(router.history.location.href, "http://localhost");
    expect(Object.fromEntries(publicUrl.searchParams)).toEqual({ domain: "7", q: "synthetic", tab: "details", return_to: "/app/", ...(view ? { nav_view: view } : {}) });
    expect(publicUrl.hash).toBe("#evidence");
    expect(router.history.length).toBe(1);
    expect(navigationRedirect(to!, {})).toBeNull();
  });

  it.each([
    "/report/security.rule-quality", "/investigations", "/investigations/42", "/cases",
    "/report/ad.new-logon-pairs",
    "/report-studio", "/report-editor", "/report-management", "/report-builder", "/admin/update", "/admin/activity",
    "/cases/42", "/report-management/42", "/report-editor/42", "/report-builder/42", "/report-builder/",
  ])("replaces a direct visit to hidden %s with home before loading the page", async (from) => {
    const root = createRootRoute({ beforeLoad: ({ location }) => navigationBeforeLoad(location) });
    const hiddenLoad = vi.fn();
    const router = createRouter({ routeTree: root.addChildren([
      createRoute({ getParentRoute: () => root, path: "/" }),
      createRoute({ getParentRoute: () => root, path: from, loader: hiddenLoad }),
    ]), basepath: "/app", history: createMemoryHistory({ initialEntries: [`/app${from}?nav_view=accounts#old-tab`] }) });
    await router.load();
    await expect.poll(() => router.history.location.pathname).toBe("/app/");
    expect(router.state.location.search).toEqual({});
    expect(router.state.location.hash).toBe("");
    expect(hiddenLoad).not.toHaveBeenCalled();
    expect(router.history.length).toBe(1);
  });

  it.each(["/", "/report/ad.users.v2", "/report/ad.users.v2/", "/report/ad.gpo.v2", "/admin/status", "/admin/plugins/sli.ad", "/admin/plugins/sli.gpo", "/setup", "/settings", "/operations/sources/fixture-host", "/events/42"])("keeps beta pages and their detail routes reachable: %s", (path) => {
    expect(navigationRedirect(path, {})).toBeNull();
  });

  it.each(["/report/file-audit.overview", "/report/file-audit.permission-changes", "/report/file-audit.actions", "/admin/plugins/sli.file-audit"])
  ("opens the File Servers workspace without preview permissions: %s", (path) => {
    expect(navigationRedirect(path, {})).toBeNull();
    expect(previewModulePath(path)).toBe(false);
  });

  it.each(["/admin/plugins/sli.remote-access", "/admin/plugins/sli.sigma",
    "/admin/plugins/sli.workstations", "/report/workstations.overview", "/extensions/sli.sigma/rules",
    "/report/vpn.connections", "/reports/vpn.audit",
  ])("retains %s so the shell can show the server-controlled availability state", (path) => {
    expect(navigationRedirect(path, {})).toBeNull();
    expect(previewModulePath(path)).toBe(true);
  });

  it("opens the event journal with a trimmed query from the shell", () => {
    expect(globalSearchTarget(" synthetic ")).toEqual({ to: "/report/events.journal", search: { q: "synthetic" } });
    expect(globalSearchTarget(" ")).toEqual({ to: "/report/events.journal", search: {} });
  });

  it("keeps the workspace selection independent of the report's internal tabs", () => {
    const params = preserveNavigationView(new URLSearchParams({ tab: "daily", domain: "7" }), "?nav_view=accounts&tab=table");
    expect(params.get("nav_view")).toBe("accounts");
    expect(params.get("tab")).toBe("daily");
  });
});
