// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import type { AgentCollectionHealth } from "../../api/client";
import { localeRuntime, setLocale, t } from "../../i18n";
import { ProjectReadinessPage } from "./readiness";

vi.mock("../App", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../App")>()),
  useEffectiveAccess: () => ({ reports: [{ report_key: "operations.readiness", allowed: true }] }),
  useTimeZone: () => ({ timeZone: "UTC" }),
}));

afterEach(() => { cleanup(); window.history.replaceState({}, "", "/"); });

it.each(["ru", "en"] as const)("renders readiness system facts in %s without treating source errors as translated labels", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  try {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
    client.setQueryData(["v4", "operations", "readiness"], {
      postgres: {}, storage: {}, workers: { items: [] },
      archive: { status: "invalid_root" },
      agent_collection: { state: "error", active_agents: 1, current_agents: 0, items: [{ ...agent, domains: ["example.test"] }] },
    });
    const { container } = render(<QueryClientProvider client={client}><ProjectReadinessPage/></QueryClientProvider>);
    expect(screen.getByRole("heading", { name: t("operations.readiness.title"), level: 1 })).toBeTruthy();
    expect(container.textContent).toContain("fixture-host");
    expect(screen.getByRole("row", { name: new RegExp(t("operations.readiness.archive.name")) }).textContent)
      .toContain(t("operations.readiness.archive.invalidRoot"));
    if (locale === "en") expect(container.textContent).not.toMatch(/[А-Яа-яЁё]/);
  } finally { cleanup(); setLocale("ru"); vi.restoreAllMocks(); }
});

const agent: AgentCollectionHealth["items"][number] = {
  id: "00000000-0000-4000-8000-000000000001", host_id: "00000000-0000-4000-8000-000000000002", name: "fixture-host", domains: ["example.test"],
  state: "error", connection: "online", last_seen: "2026-10-10T12:00:00Z", last_packet_at: "2026-10-10T11:50:00Z",
  policy_revision: 2, applied_policy_revision: 2, href: "/app/agents?agent_id=00000000-0000-4000-8000-000000000001#agent-00000000-0000-4000-8000-000000000001",
  modules: [{ module_id: "sli.workstations", channels: [{ channel: "Security", state: "error",
    last_packet_at: "2026-10-10T11:50:00Z", last_import_at: null, import_lag_seconds: 1000, budget_seconds: 900 }] }],
};

it.each([
  ["?domain=7", "", "domain=7"],
  ["?domain_id=7", "", "domain=7"],
  ["?scope=all", "", "scope=all"],
  ["?domain=7", "&domain=9", "domain=9"],
  ["?domain=7", "&scope=all", "scope=all"],
])("preserves shell scope %s for agent row and collection links only", (search, targetScope, expectedScope) => {
  window.history.replaceState({}, "", `/app/readiness${search}`);
  const href = `/app/agents?agent_id=${agent.id}${targetScope}#agent-${agent.id}`;
  const client = new QueryClient();
  client.setQueryData(["v4", "operations", "readiness"], {
    postgres: {}, storage: {}, workers: { items: [] },
    agent_collection: { state: "error", active_agents: 1, current_agents: 0,
      items: [{ ...agent, href }] },
  });
  render(<QueryClientProvider client={client}><ProjectReadinessPage/></QueryClientProvider>);
  const expected = `/app/agents?agent_id=${agent.id}&${expectedScope}#agent-${agent.id}`;
  const links = screen.getAllByRole("link");
  const agentLinks = links.filter((link) => link.getAttribute("href")?.startsWith("/app/agents"));
  expect(agentLinks.length).toBeGreaterThanOrEqual(3);
  expect(agentLinks.every((link) => link.getAttribute("href") === expected)).toBe(true);
  expect(links.filter((link) => !agentLinks.includes(link)).every((link) => !link.getAttribute("href")?.includes("domain="))).toBe(true);
});

it("renders agent groups, clocks, policy channels and links in the existing table", () => {
  const client = new QueryClient();
  client.setQueryData(["v4", "operations", "readiness"], {
    postgres: {}, storage: {},
    // A legacy response cannot add rows to this page.
    collector_health: { items: [{ server: "fixture-retired", channel: "Security", collection_state: "stale" }] },
    agent_collection: { state: "error", checked_at_utc: "2026-10-10T12:00:00Z", active_agents: 2, current_agents: 1,
      items: [agent, { ...agent, id: "fixture-paused", name: "fixture-paused", domains: ["other.example.test"], state: "paused" }] },
    workers: { items: [{ worker_name: "test-worker", label: "Test process", state: "active", feature_enabled: false }] },
  });
  render(<QueryClientProvider client={client}><ProjectReadinessPage/></QueryClientProvider>);
  expect(screen.getByRole("heading", { name: "Готовность платформы", level: 1 })).toBeTruthy();
  const row = screen.getByText("example.test · Агент: fixture-host").closest("tr")!;
  expect(within(row).getByText("Сбор нарушен")).toBeTruthy();
  expect(row.textContent).toContain("Связь: на связи");
  expect(agent.last_packet_at).toBe("2026-10-10T11:50:00Z");
  expect(row.textContent).toContain("Последний пакет: 10.10.2026, 11:50 ·");
  expect(row.textContent).toContain("sli.workstations · Security: Сбор нарушен");
  expect(row.textContent).toContain("Задержка импорта, с: 1000");
  expect(within(row).getByRole("link", { name: "Открыть агента" }).getAttribute("href")).toBe(agent.href);
  expect(within(row).getByRole("link", { name: /fixture-host/ }).getAttribute("title")).toContain(agent.id);
  expect(row.textContent).not.toContain(agent.id);
  expect(row.textContent).not.toContain(agent.host_id);
  const collection = screen.getByText("Сбор событий").closest("tr")!;
  expect(collection.textContent).toContain("Агент fixture-host · example.test: нет данных или импорта");
  expect(within(collection).getByRole("link").getAttribute("href")).toBe(agent.href);
  expect(screen.getByText("Сбор приостановлен")).toBeTruthy();
  expect(screen.queryByText(/fixture-retired/)).toBeNull();

});

it.each(["error", "waiting"] as const)("shows never-contacted %s agents as unregistered without inventing a host name", (state) => {
  const client = new QueryClient();
  client.setQueryData(["v4", "operations", "readiness"], { postgres: {}, storage: {},
    agent_collection: { state: state === "error" ? "error" : "partial", active_agents: 1, current_agents: 0, items: [
      { ...agent, state, name: "", connection: "never_seen", last_seen: null, last_packet_at: null, modules: [] },
    ] } });
  render(<QueryClientProvider client={client}><ProjectReadinessPage/></QueryClientProvider>);
  const row = screen.getByText("example.test · Агент: Имя хоста не указано").closest("tr")!;
  expect(within(row).getByText("Агент не зарегистрирован")).toBeTruthy();
  if (state === "error") expect(screen.getAllByText("Агент Имя хоста не указано · example.test: агент не зарегистрирован · время начала неизвестно").length).toBeGreaterThan(0);
  expect(screen.queryByText(/нет данных или импорта/)).toBeNull();
  expect(document.body.textContent).not.toContain(agent.id);
  expect(within(row).getByRole("link", { name: "Открыть агента" }).getAttribute("href")).toBe(agent.href);
});

it("shows unavailable collection without invented agent rows", () => {
  const client = new QueryClient();
  client.setQueryData(["v4", "operations", "readiness"], { postgres: {}, storage: {},
    agent_collection: { state: "unavailable", items: [], active_agents: 0, current_agents: 0 } });
  render(<QueryClientProvider client={client}><ProjectReadinessPage/></QueryClientProvider>);
  expect(screen.getAllByText("Состояние агентов недоступно").length).toBeGreaterThan(0);
  expect(screen.queryByText("Сбор нарушен")).toBeNull();
});

it("groups multi-domain agents with other agents in domain order", () => {
  const client = new QueryClient();
  client.setQueryData(["v4", "operations", "readiness"], { postgres: {}, storage: {},
    agent_collection: { state: "current", active_agents: 2, current_agents: 2, items: [
      { ...agent, state: "current", domains: ["a.example.test", "z.example.test"] },
      { ...agent, id: "fixture-second", name: "fixture-second", state: "current", domains: ["b.example.test"] },
    ] } });
  render(<QueryClientProvider client={client}><ProjectReadinessPage/></QueryClientProvider>);
  const rows = screen.getAllByRole("row").filter((row) => row.textContent?.includes(" · Агент:"));
  expect(rows.map((row) => row.querySelector("td")?.textContent)).toEqual([
    t("operations.agent_collection.agent", { domain: "a.example.test", agent: agent.name }),
    t("operations.agent_collection.agent", { domain: "b.example.test", agent: "fixture-second" }),
    t("operations.agent_collection.agent", { domain: "z.example.test", agent: agent.name }),
  ]);
});

