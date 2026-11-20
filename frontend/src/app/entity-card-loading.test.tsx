// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, type EntityWorkspaceDetail, type V4ObjectDetail } from "../api/client";
import { EntityCardPage } from "./entity-card";

const workspace = {
  api_version: "v1",
  entity: { id: 7, type: "ad_user", natural_key: "test-account", display_name: "Test account", first_seen_utc: "2026-09-01T08:00:00Z", last_seen_utc: "2026-09-10T12:00:00Z" },
  current_states: [], current_states_state: "available", ad_context_state: "available",
  ad_context: { resolution: "not_found", items: [], returned_count: 0, bounded: true },
  events: [], events_state: "available", events_scope_filtered: false,
  security_actions_state: "available", security_actions: [], semantic_relations_state: "available", semantic_relations: [],
  has_more: false, limits: { events: 50 },
} as EntityWorkspaceDetail;

const object: V4ObjectDetail = {
  api_version: "v4", state: "available",
  object: { object_type: "ad_user", object_id: "7", display_name: "Test account", latest_state: null },
  identity_links: [], identity_contract: "employee_and_account_are_distinct_objects",
  tabs: [], current_states: [], directory_context: { items: [] }, findings: [],
  events: [], events_state: "available", has_more_events: false, actions: [], provenance: [], limitations: [],
};

const clients: QueryClient[] = [];
beforeEach(() => { vi.stubGlobal("scrollTo", vi.fn()); });
afterEach(() => {
  cleanup();
  clients.splice(0).forEach((client) => client.clear());
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

async function open(search = "", entityType = "ad_user") {
  const detail = vi.spyOn(api, "entityWorkspace").mockResolvedValue({ ...workspace, entity: { ...workspace.entity, type: entityType } });
  vi.spyOn(api, "v4Object").mockResolvedValue({ ...object, object: { ...object.object, object_type: entityType } });
  // Keep the optional request pending: it must not block the initial profile.
  const vpn = vi.spyOn(api, "entityVpnSessions").mockImplementation(() => new Promise(() => {}));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } });
  clients.push(client);
  const root = createRootRoute();
  const route = createRoute({ getParentRoute: () => root, path: "/entities/$entityId", component: EntityCardPage, validateSearch: (value) => value });
  const router = createRouter({ routeTree: root.addChildren([route]), basepath: "/app", history: createMemoryHistory({ initialEntries: [`/app/entities/7?timezone=UTC&${search}`] }) });
  await router.load();
  render(<QueryClientProvider client={client}><RouterProvider router={router}/></QueryClientProvider>);
  await screen.findByRole("tablist");
  await waitFor(() => expect(client.getQueryData(["v4", "object", "entity", "7"])).toBeDefined());
  return { detail, vpn };
}

it.each(["", "time_from=2026-09-01&time_to=2026-09-10"])("loads VPN only after opening its tab and keeps the requested window (%s)", async (search) => {
  const { detail, vpn } = await open(search);
  expect(screen.getByRole("heading", { name: "Профиль" })).toBeTruthy();
  expect(detail).toHaveBeenCalledTimes(1);
  expect(vpn).not.toHaveBeenCalled();

  fireEvent.click(screen.getByRole("tab", { name: "VPN-сессии" }));
  await waitFor(() => expect(vpn).toHaveBeenCalledTimes(1));
  const [id, parameters] = vpn.mock.calls[0];
  expect(id).toBe("7");
  expect(parameters?.get("time_from")).toBe(search ? "2026-09-01" : "2026-08-12");
  expect(parameters?.get("time_to")).toBe("2026-09-10");
  expect(detail).toHaveBeenCalledTimes(1);
  await waitFor(() => expect(screen.getByRole("tabpanel").querySelector('[aria-busy="true"]')).toBeTruthy());

  fireEvent.click(screen.getByRole("tab", { name: "Обзор" }));
  await screen.findByRole("heading", { name: "Профиль" });
  fireEvent.click(screen.getByRole("tab", { name: "VPN-сессии" }));
  await waitFor(() => expect(screen.getByRole("tab", { name: "VPN-сессии" }).getAttribute("aria-selected")).toBe("true"));
  expect(vpn).toHaveBeenCalledTimes(1);
});

it("loads the default second slice only on the security tab and reuses it on return", async () => {
  const { detail, vpn } = await open();
  expect(detail).toHaveBeenCalledTimes(1);
  expect(detail.mock.calls[0][1]?.has("time_from")).toBe(false);
  fireEvent.click(screen.getByRole("tab", { name: "События" }));
  await screen.findByRole("heading", { name: "Сохранённые Windows-события" });
  expect(detail).toHaveBeenCalledTimes(1);

  fireEvent.click(screen.getByRole("tab", { name: "Действия безопасности" }));
  await waitFor(() => expect(detail).toHaveBeenCalledTimes(2));
  expect(detail.mock.calls[1][1]?.get("time_from")).toBe("2026-08-12");
  expect(detail.mock.calls[1][1]?.get("time_to")).toBe("2026-09-10");
  expect(vpn).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("tab", { name: "Обзор" }));
  await screen.findByRole("heading", { name: "Профиль" });
  fireEvent.click(screen.getByRole("tab", { name: "Действия безопасности" }));
  await waitFor(() => expect(screen.getByRole("tab", { name: "Действия безопасности" }).getAttribute("aria-selected")).toBe("true"));
  expect(detail).toHaveBeenCalledTimes(2);
});

it.each(["vpn", "security"])("loads a directly linked optional tab (%s)", async (tab) => {
  const { detail, vpn } = await open(`tab=${tab}`);
  await waitFor(() => expect(tab === "vpn" ? vpn : detail).toHaveBeenCalledTimes(tab === "vpn" ? 1 : 2));
  expect(tab === "vpn" ? detail : vpn).toHaveBeenCalledTimes(tab === "vpn" ? 1 : 0);
});

it("uses the main slice for an explicit security window", async () => {
  const { detail, vpn } = await open("tab=security&time_from=2026-09-01&time_to=2026-09-10");
  expect(screen.getByRole("tab", { name: "Действия безопасности" }).getAttribute("aria-selected")).toBe("true");
  expect(detail).toHaveBeenCalledTimes(1);
  expect(vpn).not.toHaveBeenCalled();
});

it("does not load VPN for a hidden tab on an unsupported entity type", async () => {
  const { detail, vpn } = await open("tab=vpn", "ad_group");
  expect(screen.queryByRole("tab", { name: "VPN-сессии" })).toBeNull();
  expect(screen.getByRole("heading", { name: "Профиль" })).toBeTruthy();
  expect(detail).toHaveBeenCalledTimes(1);
  expect(vpn).not.toHaveBeenCalled();
});
