import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { expect, it, vi } from "vitest";

const mutationScenario = vi.hoisted(() => ({ action: "create" as "create" | "add_evidence", calls: 0 }));

vi.mock("@tanstack/react-query", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@tanstack/react-query")>();
  return {
    ...actual,
    useMutation: () => {
      const call = mutationScenario.calls++;
      const successful = (mutationScenario.action === "create" && call === 0)
        || (mutationScenario.action === "add_evidence" && call === 1);
      return call === 0
        ? { variables: successful ? { eventDbId: 517548 } : undefined, data: successful ? { id: 71 } : undefined, isPending: false, isError: false, isSuccess: successful, mutate: vi.fn() }
        : { variables: successful ? { caseId: 72, eventDbId: 517548 } : undefined, isPending: false, isError: false, isSuccess: successful, mutate: vi.fn() };
    },
  };
});

import { EventCardPage } from "./event-card";
import { InvestigationCasePage } from "./case-page";

it.each([
  ["create", 71],
  ["add_evidence", 72],
] as const)("actual report → event → %s-case success UI leads to a case return path", async (action, caseId) => {
  mutationScenario.action = action;
  mutationScenario.calls = 0;
  const report = "/app/security-events-report?tab=events&domain_id=7&time_from=2026-09-11T10%3A20%3A30.123456Z&time_to=2026-09-11T11%3A20%3A30.987654Z&timezone=Asia%2FBangkok&target=S-1-5-21-affected";
  const eventPath = `/app/events/517548?return_to=${encodeURIComponent(report)}`;
  const eventClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  eventClient.setQueryData(["bootstrap"], { effective_role: "viewer" });
  eventClient.setQueryData(["event", "517548"], { item: {
    event_db_id: 517548, event_id: 4722, time_created_utc: "2026-09-11T10:25:00Z", subject: "admin", target: "S-1-5-21-affected",
    server: "dc01.example.test", source: null, provider_name: null, event_record_id: null, event_data: {}, message_text: null,
    semantics: { title: "Изменение учётной записи", final_risk: "low", risk: "Низкий", assessment_confidence: "unknown", summary: "Наблюдение.", facts: [], checks: [], known: true, classification_origin: "catalog_base", card_completeness: "not_applicable" },
  } });
  eventClient.setQueryData(["event-relations", "517548"], { items: [] });
  eventClient.setQueryData(["event-entities", "517548"], { items: [] });
  eventClient.setQueryData(["investigation-cases"], { items: [{ id: 72, title: "Existing" }] });
  const root = createRootRoute();
  const event = createRoute({ getParentRoute: () => root, path: "/events/$eventId", component: EventCardPage });
  const investigations = createRoute({ getParentRoute: () => root, path: "/investigations", component: () => null });
  const router = createRouter({ routeTree: root.addChildren([event, investigations]), basepath: "/app", history: createMemoryHistory({ initialEntries: [eventPath] }) });
  const globalScope = globalThis as unknown as { window?: { location: { href: string; search: string; pathname: string } } };
  const hadWindow = Object.hasOwn(globalScope, "window");
  const previousWindow = globalScope.window;
  globalScope.window = { location: { href: `http://localhost${eventPath}`, search: eventPath.slice(eventPath.indexOf("?")), pathname: "/app/events/517548" } };
  try {
    await router.load();
    const eventHtml = renderToStaticMarkup(<QueryClientProvider client={eventClient}><RouterProvider router={router} /></QueryClientProvider>);
    const caseHref = eventHtml.match(new RegExp(`<a href="([^"]+)" data-case-mutation="${action}">Открыть дело #INV-${String(caseId).padStart(7, "0")}</a>`))?.[1];
    expect(caseHref).toBeDefined();
    const caseUrl = new URL(caseHref!.replaceAll("&amp;", "&"), "http://localhost");
    expect(caseUrl.searchParams.get("event_db_id")).toBe("517548");
    expect(caseUrl.searchParams.get("return_to")).toBe(report);

    const caseClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
    caseClient.setQueryData(["bootstrap"], { effective_role: "viewer" });
    caseClient.setQueryData(["investigation-case", String(caseId), 517548, undefined, undefined], { id: caseId, title: "Case", status: "open", owner: null, created_at: "2026-09-11T10:30:00Z", created_by: "analyst", events: [], notes: [], audit: [] });
    const caseRoot = createRootRoute();
    const caseRoute = createRoute({ getParentRoute: () => caseRoot, path: "/investigations/$investigationId", component: InvestigationCasePage });
    const caseListRoute = createRoute({ getParentRoute: () => caseRoot, path: "/investigations", component: () => null });
    const caseRouter = createRouter({ routeTree: caseRoot.addChildren([caseRoute, caseListRoute]), basepath: "/app", history: createMemoryHistory({ initialEntries: [caseUrl.pathname + caseUrl.search] }) });
    await caseRouter.load();
    const caseHtml = renderToStaticMarkup(<QueryClientProvider client={caseClient}><RouterProvider router={caseRouter} /></QueryClientProvider>);
    const reportHref = caseHtml.match(/href="([^"]+)"[^>]*>Вернуться к исходному отчёту/)?.[1];
    expect(reportHref?.replaceAll("&amp;", "&")).toBe(report);
  } finally {
    if (hadWindow) globalScope.window = previousWindow;
    else Reflect.deleteProperty(globalScope, "window");
  }
});
