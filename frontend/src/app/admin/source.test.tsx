// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ detail: vi.fn() }));

vi.mock("../App", async (importOriginal) => ({ ...(await importOriginal<typeof import("../App")>()), useTimeZone: () => ({ timeZone: "UTC" }) }));
vi.mock("../../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../api/client")>();
  return { ...actual, api: { ...actual.api, sourceDetail: (hostname: string) => state.detail(hostname) } };
});

import { SourceDetailPage } from "./source";

async function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const root = createRootRoute();
  const route = createRoute({ getParentRoute: () => root, path: "/operations/sources/$hostname", component: SourceDetailPage });
  const router = createRouter({ routeTree: root.addChildren([route]), history: createMemoryHistory({ initialEntries: ["/operations/sources/DC%2001"] }) });
  await router.load();
  return render(<QueryClientProvider client={client}><RouterProvider router={router}/></QueryClientProvider>);
}

beforeEach(() => { vi.stubGlobal("scrollTo", vi.fn()); });
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.clearAllMocks(); });

it("loads the source by the route hostname and keeps missing inventory honest", async () => {
  state.detail.mockResolvedValue({
    api_version: "v1", generated_at_utc: "2026-09-30T10:00:00Z", read_only: true,
    source: { hostname: "DC 01", ip_addresses: [], disk_state: "unknown", disks: [{ name: "C:" }] },
    collection_freshness: { state: "lagging", label: "Отстаёт", collection_error: false },
    channels: [{ server: "DC 01", channel: "Security", last_successful_collection_utc: null, last_event_time_utc: null, collection_label: "Не подтверждено" }],
    limitations: ["Инвентаризация неполная"],
  });
  await mount();
  expect(await screen.findByText("DC 01", { selector: "h1" })).toBeTruthy();
  expect(state.detail).toHaveBeenCalledWith("DC 01");
  expect(screen.getByText("не собраны", { selector: ".sli-ds-metric__value" })).toBeTruthy();
  expect(screen.getAllByRole("cell", { name: "—" }).length).toBeGreaterThan(0);
  expect(screen.getByText("Инвентаризация неполная")).toBeTruthy();
  expect(screen.queryByText("0 Б")).toBeNull();
  expect(screen.getByText("не получена").closest(".sli-ds-metric")?.getAttribute("data-tone")).toBe("neutral");
  expect(screen.getByText("Не подтверждено").getAttribute("data-tone")).toBeNull();
});

it.each([
  ["current", "ok", "success"], ["error", "failed", "danger"],
  ["stale", "timeout", "danger"], ["lagging", "warning", "warning"],
  ["unknown", "unknown", "neutral"], ["future_ok", "future_ok", "neutral"],
])("colours source channels and inventory from exact states (%s)", async (channelState, diskState, tone) => {
  state.detail.mockResolvedValue({
    source: { hostname: "fixture-source", os_name: "Fixture OS", ip_addresses: [], disk_state: diskState, disks: [] },
    collection_freshness: { state: channelState, label: "Fixture freshness" },
    channels: [{ server: "fixture-source", channel: "Fixture", collection_state: channelState, last_status: "ok", collection_label: "Fixture channel state" }],
    limitations: [],
  });
  await mount();
  expect((await screen.findByText("Fixture OS")).closest(".sli-ds-metric")?.getAttribute("data-tone")).toBe("success");
  expect(screen.getByText("Fixture channel state").getAttribute("data-tone")).toBe(tone === "neutral" ? null : tone);
  expect(screen.getByText("Fixture freshness").getAttribute("data-tone")).toBe(tone === "neutral" ? null : tone);
  expect(screen.getByText("Диски", { selector: ".sli-ds-metric__label" }).closest(".sli-ds-metric")?.getAttribute("data-tone")).toBe(tone);
});

it("shows an unavailable state when the source cannot be read", async () => {
  state.detail.mockRejectedValue(new Error("Источник не найден"));
  await mount();
  expect((await screen.findByRole("alert")).textContent).toContain("Источник не найден");
});
