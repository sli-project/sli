/** @vitest-environment jsdom */
import { renderToStaticMarkup } from "react-dom/server";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { afterEach, expect, it, vi } from "vitest";
import { ApiResponseError } from "../api/client";
import { InvestigationCasePage } from "./case-page";
import { localeRuntime, setLocale } from "../i18n";

afterEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("ru");
  vi.restoreAllMocks();
});

it("renders case controls in English while retaining the stored case title and notes", async () => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("en");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["investigation-case", "7", null, undefined, undefined], { id: 7, title: "Синтетическое дело", status: "open", owner: null, created_by: "synthetic", events: [], notes: [{ id: 1, body: "Синтетическая заметка" }], audit: [] });
  client.setQueryData(["bootstrap"], {});
  const root = createRootRoute();
  const cases = createRoute({ getParentRoute: () => root, path: "/investigations/$investigationId", component: InvestigationCasePage });
  const list = createRoute({ getParentRoute: () => root, path: "/investigations", component: () => null });
  const router = createRouter({ routeTree: root.addChildren([cases, list]), basepath: "/app", history: createMemoryHistory({ initialEntries: ["/app/investigations/7"] }) });
  await router.load();
  const html = renderToStaticMarkup(<QueryClientProvider client={client}><RouterProvider router={router}/></QueryClientProvider>);
  expect(html).toContain("Event chain");
  expect(html).toContain("Minimum risk");
  expect(html).toContain("Selected event");
  expect(html).toContain("· author:");
  expect(html).toContain("Синтетическое дело");
  expect(html).toContain("Синтетическая заметка");
  expect(html).not.toContain("Контекст загружается");
});

it.each([false, true])("case return link preserves exact evidence and period (unavailable=%s)", async (unavailable) => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, retryOnMount: false, staleTime: Infinity } } });
  const queryKey = ["investigation-case", "7", 12, undefined, undefined];
  if (unavailable) {
    client.getQueryCache().build(client, { queryKey }).setState({ status: "error", error: new Error("not found"), fetchStatus: "idle" });
  } else {
    client.setQueryData(queryKey, { id: 7, title: "Case", status: "open", owner: null, events: [], notes: [], audit: [] });
  }
  const root = createRootRoute();
  const cases = createRoute({ getParentRoute: () => root, path: "/investigations/$investigationId", component: InvestigationCasePage });
  const investigation = createRoute({ getParentRoute: () => root, path: "/investigations", component: () => null });
  const router = createRouter({ routeTree: root.addChildren([cases, investigation]), basepath: "/app",
    history: createMemoryHistory({ initialEntries: ["/app/investigations/7?event_db_id=12&scope=all&time_from=2026-09-10&time_to=2026-09-11&timezone=UTC"] }) });
  await router.load();
  const html = renderToStaticMarkup(<QueryClientProvider client={client}><RouterProvider router={router} /></QueryClientProvider>);
  const href = html.match(/href="([^"]+)"[^>]*>(?:Расследования|Вернуться к расследованиям)</)?.[1];
  expect(href).toBeDefined();
  const url = new URL(href!.replaceAll("&amp;", "&"), "http://localhost");
  expect(url.pathname).toBe("/app/investigations");
  expect(Object.fromEntries(url.searchParams)).toEqual({ event_db_id: "12", scope: "all", time_from: "2026-09-10", time_to: "2026-09-11", timezone: "UTC" });
});

it("case selected proof keeps its exact evidence and context", async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, retryOnMount: false, staleTime: Infinity } } });
  client.setQueryData(["investigation-case", "7", 517548, undefined, undefined], { id: 7, title: "Case", status: "open", owner: null, created_at: "2026-09-10T12:00:00Z", created_by: "analyst", events: [{ event_db_id: 517548, relation_status: "confirmed", added_at: "2026-09-10T12:00:00Z" }], notes: [], audit: [] });
  client.setQueryData(["events-batch", [517548]], { items: [{ event_db_id: 517548, event_id: 4624, time_created_utc: "2026-09-10T22:35:00Z", subject: null, target: null, server: null, channel: null, semantics: { title: "Успешный вход", final_risk: "low", risk: "Низкий", assessment_confidence: "unknown", summary: "Наблюдение входа.", facts: [], checks: [], known: true, classification_origin: "catalog_base", card_completeness: "not_applicable" } }] });
  client.setQueryData(["bootstrap"], {});
  const root = createRootRoute();
  const cases = createRoute({ getParentRoute: () => root, path: "/investigations/$investigationId", component: InvestigationCasePage });
  const investigation = createRoute({ getParentRoute: () => root, path: "/investigations", component: () => null });
  const event = createRoute({ getParentRoute: () => root, path: "/events/$eventId", component: () => null });
  const router = createRouter({ routeTree: root.addChildren([cases, investigation, event]), basepath: "/app", history: createMemoryHistory({ initialEntries: ["/app/investigations/7?event_db_id=517548&entity_id=5632&scope=all&time_from=2026-09-10T12%3A00%3A00.123001Z&time_to=2026-09-10T12%3A00%3A00.123999Z&timezone=UTC"] }) });
  await router.load();
  const html = renderToStaticMarkup(<QueryClientProvider client={client}><RouterProvider router={router} /></QueryClientProvider>);
  const href = html.match(/href="([^"]+)"[^>]*>Открыть полностью</)?.[1];
  expect(href).toBeDefined();
  const url = new URL(href!.replaceAll("&amp;", "&"), "http://localhost");
  expect(url.pathname).toBe("/app/events/517548");
  expect(Object.fromEntries(url.searchParams)).toEqual({ event_db_id: "517548", entity_id: "5632", scope: "all", time_from: "2026-09-10T12:00:00.123001Z", time_to: "2026-09-10T12:00:00.123999Z", timezone: "UTC" });
  expect(html).toContain("22:35:00");
  expect(html).not.toContain("05:35:00");
  expect(html).toContain("Класс каталога: низкий");
  expect(html).not.toContain("Класс события: низкий");
  expect(html).not.toContain("Риск ИБ: low");
  expect(html).not.toContain("Уверенность: unknown");
});

it.each([
  ["temporary failure", new Error("archive unavailable"), "Контекст доказательства временно недоступен."],
  ["access denial", new ApiResponseError(403, "insufficient_permissions", "forbidden"), "Нет разрешения на просмотр контекста доказательства."],
])("case reports %s instead of loading forever", async (_scenario, batchError, expectedMessage) => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, retryOnMount: false, staleTime: Infinity } } });
  client.setQueryData(["investigation-case", "7", null, undefined, undefined], { id: 7, title: "Case", status: "open", owner: null, created_at: "2026-09-10T12:00:00Z", created_by: "analyst", events: [{ event_db_id: 517548, relation_status: "confirmed", added_at: "2026-09-10T12:00:00Z" }], notes: [], audit: [] });
  client.getQueryCache().build(client, { queryKey: ["events-batch", [517548]] }).setState({ status: "error", error: batchError, fetchStatus: "idle" });
  client.setQueryData(["bootstrap"], {});
  const root = createRootRoute();
  const cases = createRoute({ getParentRoute: () => root, path: "/investigations/$investigationId", component: InvestigationCasePage });
  const investigation = createRoute({ getParentRoute: () => root, path: "/investigations", component: () => null });
  const event = createRoute({ getParentRoute: () => root, path: "/events/$eventId", component: () => null });
  const router = createRouter({ routeTree: root.addChildren([cases, investigation, event]), basepath: "/app", history: createMemoryHistory({ initialEntries: ["/app/investigations/7?time_from=2026-09-10&time_to=2026-09-11&timezone=UTC"] }) });
  await router.load();
  const html = renderToStaticMarkup(<QueryClientProvider client={client}><RouterProvider router={router} /></QueryClientProvider>);
  expect(html).toContain(expectedMessage);
  expect(html).not.toContain("Контекст загружается");
  expect(html).not.toContain("Загружаем точную карточку evidence");
});

it("renders saved event titles and summaries in English while retaining case titles and notes", async () => {
  const scroll = vi.spyOn(window, "scrollTo").mockImplementation(() => undefined);
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("en");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["investigation-case", "7", null, undefined, undefined], { id: 7, title: "Синтетическое дело", status: "open", created_at: "2026-01-01T00:00:00Z", created_by: "fixture", events: [{ event_db_id: 77, relation_status: "confirmed", added_at: "2026-01-01T00:00:00Z" }], notes: [{ id: 1, body: "Синтетическая заметка" }], audit: [] });
  const code = "Security:Microsoft-Windows-Security-Auditing:4740";
  client.setQueryData(["events-batch", [77]], { items: [{ event_db_id: 77, event_id: 4740, semantics: { title: "Блокировка учетной записи", title_code: `${code}.title`, summary: "Серверное описание", summary_code: `${code}.summary` } }] });
  client.setQueryData(["bootstrap"], {});
  const root = createRootRoute();
  const cases = createRoute({ getParentRoute: () => root, path: "/investigations/$investigationId", component: InvestigationCasePage });
  const list = createRoute({ getParentRoute: () => root, path: "/investigations", component: () => null });
  const router = createRouter({ routeTree: root.addChildren([cases, list]), basepath: "/app", history: createMemoryHistory({ initialEntries: ["/app/investigations/7"] }) });
  try {
    await router.load();
    render(<QueryClientProvider client={client}><RouterProvider router={router}/></QueryClientProvider>);
    expect(await screen.findByText("A lockout helps find the source of incorrect logon attempts and possible brute force.")).toBeTruthy();
    expect(screen.getAllByText("Account locked out").length).toBeGreaterThan(0);
    expect(screen.getByText("Синтетическое дело")).toBeTruthy();
    expect(screen.getByText("Синтетическая заметка")).toBeTruthy();
    expect(screen.queryByText("Блокировка учетной записи")).toBeNull();
  } finally { cleanup(); client.clear(); setLocale("ru"); scroll.mockRestore(); }
});
