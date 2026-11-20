// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, ApiResponseError } from "../api/client";
import { localeRuntime, setLocale, t } from "../i18n";
import { AppShell } from "./App";
import { CapabilityGate } from "./admin/gate";
import { AgentsPage } from "./admin/agents";
import { ProjectReadinessPage } from "./admin/readiness";
import { AccessCenterPage, AccessRequestsPage } from "./admin/access";
import { CaseListPage } from "./cases";

vi.mock("../api/client", async (original) => {
  const actual = await original<typeof import("../api/client")>();
  return { ...actual, api: { ...actual.api,
    bootstrap: vi.fn().mockResolvedValue({ capabilities: [], principal: { username: "test.operator" } }),
    v4Access: vi.fn(),
    reportsV2Catalog: vi.fn().mockResolvedValue({ items: [] }),
    agentCollection: vi.fn().mockResolvedValue({}),
    agents: vi.fn().mockResolvedValue({ items: [] }),
    platformReadiness: vi.fn().mockResolvedValue({}),
    investigationCases: vi.fn().mockResolvedValue({ items: [] }),
  } };
});

const granted: Awaited<ReturnType<typeof api.v4Access>> = {
  api_version: "v4", evaluated_at_utc: "2026-10-21T00:00:00Z", preview: false,
  subject: { type: "user", username: "test.operator", coarse_role: "operator" },
  capabilities: ["access.manage"], reports: [], platform_owner: false,
  groups: [], packages: [], package_explain: [], capability_explain: {},
  allowed_report_count: 0, navigation: [], explicit_denies: { packages: [], capabilities: [], reports: [] },
};
const noGrants = { ...granted, capabilities: [] };
const CapabilityPage = () => <CapabilityGate title="Capability screen" anyOf={["access.manage"]} label="manage"><p>Protected content</p></CapabilityGate>;
const pages = [CapabilityPage, AgentsPage, ProjectReadinessPage, AccessCenterPage, AccessRequestsPage, CaseListPage];
const clients: QueryClient[] = [];

async function mount(component: () => React.JSX.Element) {
  const root = createRootRoute({ component: AppShell });
  const page = createRoute({ getParentRoute: () => root, path: "/", component });
  const router = createRouter({ routeTree: root.addChildren([page]), history: createMemoryHistory({ initialEntries: ["/"] }) });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  clients.push(client);
  render(<QueryClientProvider client={client}><RouterProvider router={router}/></QueryClientProvider>);
  await screen.findByRole("main");
  return client;
}

beforeEach(() => { vi.clearAllMocks(); window.scrollTo = () => undefined; });
afterEach(() => { cleanup(); clients.splice(0).forEach((client) => client.clear()); });

describe.each(pages)("effective access for $name", (Page) => {
  it.each([
    ["network", new TypeError("Failed to fetch"), "unavailable"],
    ["403", new ApiResponseError(403), "denied"],
    ["401", new ApiResponseError(401), "denied"],
    ["503", new ApiResponseError(503), "unavailable"],
  ] as const)("shows terminal %s failure and retries access without reload", async (_name, error, expected) => {
    vi.mocked(api.v4Access).mockRejectedValueOnce(error);
    await mount(Page);
    const main = within(screen.getByRole("main"));
    await waitFor(() => expect(main.getByRole("alert").getAttribute("data-state")).toBe(expected));
    expect(main.queryByText("Protected content")).toBeNull();
    expect(api.agents).not.toHaveBeenCalled();
    expect(api.platformReadiness).not.toHaveBeenCalled();
    expect(api.investigationCases).not.toHaveBeenCalled();
    vi.mocked(api.v4Access).mockResolvedValueOnce(noGrants);
    fireEvent.click(main.getByRole("button", { name: t("state.retry") }));
    await waitFor(() => expect(api.v4Access).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(main.getByRole("alert").getAttribute("data-state")).toBe("denied"));
    await waitFor(() => expect(main.queryByRole("button", { name: t("state.retry") })).toBeNull());
    expect(main.queryByText("Protected content")).toBeNull();
  });

  it("keeps pending access loading and does not fetch protected data", async () => {
    vi.mocked(api.v4Access).mockReturnValue(new Promise(() => undefined));
    await mount(Page);
    await waitFor(() => expect(screen.getByRole("main").querySelector('[aria-busy="true"]')).not.toBeNull());
    expect(within(screen.getByRole("main")).queryByRole("alert")).toBeNull();
    expect(api.agents).not.toHaveBeenCalled();
    expect(api.platformReadiness).not.toHaveBeenCalled();
    expect(api.investigationCases).not.toHaveBeenCalled();
  });
});

it("recovers to granted content after a failed request and keeps retry pending truthful", async () => {
  vi.mocked(api.v4Access).mockRejectedValueOnce(new ApiResponseError(503));
  await mount(CapabilityPage);
  const main = within(screen.getByRole("main"));
  const retry = await main.findByRole("button", { name: t("state.retry") });
  let resolve!: (value: typeof granted) => void;
  vi.mocked(api.v4Access).mockReturnValueOnce(new Promise((done) => { resolve = done; }));
  fireEvent.click(retry);
  await waitFor(() => expect(screen.getByRole("main").querySelector('[aria-busy="true"]')).not.toBeNull());
  await act(async () => resolve(granted));
  expect(await main.findByText("Protected content")).toBeTruthy();
});

it("hides cached protected content when access refetch is forbidden", async () => {
  vi.mocked(api.v4Access).mockResolvedValueOnce(granted);
  const client = await mount(CapabilityPage);
  expect(await screen.findByText("Protected content")).toBeTruthy();
  vi.mocked(api.v4Access).mockRejectedValueOnce(new ApiResponseError(403));
  await act(async () => { await client.invalidateQueries({ queryKey: ["v4", "access", "shell"] }); });
  await waitFor(() => expect(within(screen.getByRole("main")).getByRole("alert").getAttribute("data-state")).toBe("denied"));
  expect(screen.queryByText("Protected content")).toBeNull();
});

 it("uses existing English state and retry translations", async () => {
  const reload = vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("en");
  try {
    vi.mocked(api.v4Access).mockRejectedValueOnce(new ApiResponseError(503));
    await mount(CapabilityPage);
    const main = within(screen.getByRole("main"));
    expect(await main.findByText(t("state.unavailable.title"))).toBeTruthy();
    expect(main.getByRole("button", { name: t("state.retry") })).toBeTruthy();
  } finally {
    setLocale("ru");
    reload.mockRestore();
  }
});
