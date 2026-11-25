// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fixture from "../../../config/navigation_v3.json";
import type { NavigationRegistryDto } from "../api/report-v2-types";

const state = vi.hoisted(() => ({ grants: [] as string[], status: "получены", catalogFails: false }));
vi.mock("./App", () => ({
  useAccessStatus: () => state.status,
  useEffectiveAccess: () => state.status === "получены" ? {
    reports: state.grants.map((report_key) => ({ report_key, allowed: true })),
  } : undefined,
}));
vi.mock("../api/client", () => ({ api: { reportsV2Catalog: vi.fn() } }));
vi.mock("../plugins/routes", () => ({ PluginReportPage: ({ reportKey }: { reportKey: string }) => <p data-testid="report">{reportKey}</p> }));
vi.mock("./report-v2/ReportRenderer", () => ({ ReportRenderer: ({ reportKey, additionalTabs, onAdditionalTab }: {
  reportKey: string; additionalTabs: { key: string; label: string }[]; onAdditionalTab: (key: string) => void;
}) => <><p data-testid="report">{reportKey}</p>{additionalTabs.map((tab) =>
  <button key={tab.key} role="tab" onClick={() => onAdditionalTab(tab.key)}>{tab.label}</button>)}</> }));
import { api } from "../api/client";
import { ReportWorkspacePage } from "./report-workspace";

async function renderWorkspace(reportKey: string, query = "", disabled = false) {
  const registry = fixture as NavigationRegistryDto;
  vi.mocked(api.reportsV2Catalog).mockImplementation(async () => {
    if (state.catalogFails) throw new Error("synthetic-unavailable");
    return { contract_id: "sli.report-catalog.v2", items: [], navigation: {
      ...registry, sections: disabled ? [] : registry.sections,
    } };
  });
  window.history.replaceState(null, "", `/app/report/${reportKey}${query}`);
  const root = createRootRoute();
  const route = createRoute({ getParentRoute: () => root, path: "/report/$reportKey", component: () => <ReportWorkspacePage reportKey={reportKey}/> });
  const router = createRouter({ routeTree: root.addChildren([route]), basepath: "/app",
    history: createMemoryHistory({ initialEntries: [`/app/report/${reportKey}${query}`] }) });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><RouterProvider router={router}/></QueryClientProvider>);
  await router.load();
  return router;
}

beforeEach(() => { vi.spyOn(window, "scrollTo").mockImplementation(() => undefined); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); state.grants = []; state.status = "получены"; state.catalogFails = false; });

describe("registry report workspaces", () => {
  it("opens VPN connections with its existing report filters and without an unavailable accounts tab", async () => {
    state.grants = ["vpn.audit"];
    const router = await renderWorkspace("vpn.connections", "?domain=7&tab=daily");
    expect((await screen.findByTestId("report")).textContent).toBe("vpn.connections");
    expect(new URLSearchParams(router.state.location.searchStr).get("domain")).toBe("7");
    expect(new URLSearchParams(router.state.location.searchStr).get("tab")).toBe("daily");
    expect(screen.queryByRole("tab", { name: "VPN-доступ учётных записей" })).toBeNull();
  });

  it("does not mount the unavailable accounts report from a saved VPN workspace URL", async () => {
    state.grants = ["vpn.audit"];
    await renderWorkspace("vpn.connections", "?nav_view=accounts&tab=details&q=synthetic");
    expect((await screen.findByRole("alert")).getAttribute("data-state")).toBe("denied");
    expect(screen.queryByTestId("report")).toBeNull();
  });

  it("keeps a domain_id deep link when switching from computers to logons", async () => {
    state.grants = ["ad.computers.v6", "ad.computer-logons"];
    const router = await renderWorkspace("ad.computers.v6", "?domain_id=8");
    expect((await screen.findByTestId("report")).textContent).toBe("ad.computers.v6");
    expect(screen.queryByRole("tablist")).toBeNull();
    expect(screen.queryByRole("tab", { name: "Компьютеры" })).toBeNull();
    fireEvent.click(screen.getByRole("tab", { name: "Входы на компьютеры" }));
    await waitFor(() => expect(screen.getByTestId("report").textContent).toBe("ad.computer-logons"));
    expect(String((router.state.location.search as Record<string, unknown>).domain_id)).toBe("8");
    expect(new URLSearchParams(router.state.location.searchStr).get("domain_id")).toBe("8");
  });

  it("gives a logons-only reader a working computers entry without mounting the computer report", async () => {
    state.grants = ["ad.computer-logons"];
    await renderWorkspace("ad.computers.v6");
    expect((await screen.findByTestId("report")).textContent).toBe("ad.computer-logons");
    expect(screen.queryByRole("tab", { name: "Компьютеры" })).toBeNull();
  });

  it("does not mount a denied view named by a direct URL", async () => {
    state.grants = ["ad.computers.v6"];
    await renderWorkspace("ad.computers.v6", "?nav_view=logons");
    expect((await screen.findByRole("alert")).getAttribute("data-state")).toBe("denied");
    expect(screen.queryByTestId("report")).toBeNull();
  });

  it("keeps granted historical report views reachable when the plugin is hidden from navigation", async () => {
    state.grants = ["vpn.audit"];
    await renderWorkspace("vpn.connections", "?nav_view=connections", true);
    expect((await screen.findByTestId("report")).textContent).toBe("vpn.connections");
  });

  it.each(["access", "catalog"])("shows unavailable when %s fails", async (failure) => {
    state.status = failure === "access" ? "отказ" : "получены";
    state.catalogFails = failure === "catalog";
    await renderWorkspace("vpn.connections");
    expect((await screen.findByRole("alert")).getAttribute("data-state")).toBe("unavailable");
    expect(screen.queryByTestId("report")).toBeNull();
  });
});

it("leaves file-audit tabs to its own renderer", async () => {
  state.grants = ["file-audit.overview", "file-audit.actions"];
  await renderWorkspace("file-audit.overview");
  expect((await screen.findByTestId("report")).textContent).toBe("file-audit.overview");
  expect(screen.queryByRole("tablist")).toBeNull();
});
