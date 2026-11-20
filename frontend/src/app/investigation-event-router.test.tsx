import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { expect, it } from "vitest";
import { EventCaseMutationOutcome, EventCardPage } from "./event-card";
import { InvestigationCasePage } from "./case-page";

it("case navigation recovers the validated originating report context and rejects an external return target", async () => {
  const pages = await import("./event-card") as typeof import("./event-card") & {
    eventCaseNavigationHref?: (caseId: number, eventDbId: number, returnTo: string | null | undefined) => string | null;
  };
  expect(pages.eventCaseNavigationHref).toBeTypeOf("function");
  const href = pages.eventCaseNavigationHref!(7, 517548,
    "/app/security-events-report?domain_id=7&time_from=2026-09-11T10%3A20%3A30.123456Z&time_to=2026-09-11T11%3A20%3A30.987654Z&timezone=Asia%2FBangkok&category=account_change&target=S-1-5-21-affected",
  );
  const url = new URL(href!, "http://localhost");
  expect(url.pathname).toBe("/app/investigations/7");
  expect(Object.fromEntries(url.searchParams)).toEqual({
    event_db_id: "517548",
    scope: "all",
    time_from: "2026-09-11T10:20:30.123456Z",
    time_to: "2026-09-11T11:20:30.987654Z",
    timezone: "Asia/Bangkok",
    return_to: "/app/security-events-report?domain_id=7&time_from=2026-09-11T10%3A20%3A30.123456Z&time_to=2026-09-11T11%3A20%3A30.987654Z&timezone=Asia%2FBangkok&category=account_change&target=S-1-5-21-affected",
  });
  expect(pages.eventCaseNavigationHref!(7, 517548, "https://attacker.example/case")).toBeNull();
});

it.each([
  ["create", 71],
  ["add_evidence", 72],
] as const)("event case %s success UI opens a case that returns to the exact selected report", async (action, caseId) => {
  const report = "/app/security-events-report?tab=events&domain_id=7&time_from=2026-09-11T10%3A20%3A30.123456Z&time_to=2026-09-11T11%3A20%3A30.987654Z&timezone=Asia%2FBangkok&target=S-1-5-21-affected";
  const outcomeHtml = renderToStaticMarkup(<EventCaseMutationOutcome caseId={caseId} eventDbId={517548} returnTo={report} action={action} />);
  expect(outcomeHtml).toContain(`data-case-mutation="${action}"`);
  const caseHref = outcomeHtml.match(/href="([^"]+)"/)?.[1];
  expect(caseHref).toBeDefined();
  const caseUrl = new URL(caseHref!.replaceAll("&amp;", "&"), "http://localhost");
  expect(caseUrl.pathname).toBe(`/app/investigations/${caseId}`);
  expect(caseUrl.searchParams.get("event_db_id")).toBe("517548");
  expect(caseUrl.searchParams.get("return_to")).toBe(report);

  const client = new QueryClient({ defaultOptions: { queries: { retry: false, retryOnMount: false, staleTime: Infinity } } });
  client.setQueryData(["bootstrap"], { effective_role: "viewer" });
  client.setQueryData(["investigation-case", String(caseId), 517548, undefined, undefined], { id: caseId, title: "Case", status: "open", owner: null, created_at: "2026-09-11T10:30:00Z", created_by: "analyst", events: [], notes: [], audit: [] });
  const root = createRootRoute();
  const cases = createRoute({ getParentRoute: () => root, path: "/investigations/$investigationId", component: InvestigationCasePage });
  const investigations = createRoute({ getParentRoute: () => root, path: "/investigations", component: () => null });
  const router = createRouter({ routeTree: root.addChildren([cases, investigations]), basepath: "/app", history: createMemoryHistory({ initialEntries: [caseUrl.pathname + caseUrl.search] }) });
  await router.load();
  const caseHtml = renderToStaticMarkup(<QueryClientProvider client={client}><RouterProvider router={router} /></QueryClientProvider>);
  const reportHref = caseHtml.match(/href="([^"]+)"[^>]*>Вернуться к исходному отчёту/)?.[1];
  expect(reportHref?.replaceAll("&amp;", "&")).toBe(report);
});

it("event detail Link keeps the exact numeric evidence ID unquoted", async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["bootstrap"], { effective_role: "viewer" });
  client.setQueryData(["event", "542920"], { item: {
    event_db_id: 542920, event_id: 4624, time_created_utc: "2026-09-10T12:00:00Z",
    subject: "—", target: null, server: null, source: null, provider_name: null,
    event_record_id: null, event_data: {}, message_text: null,
    semantics: { title: "Успешный вход", final_risk: "low", risk: "Низкий", assessment_confidence: "unknown", summary: "Наблюдение входа.", facts: [], checks: [], known: true, classification_origin: "catalog_base", card_completeness: "not_applicable" },
  } });
  client.setQueryData(["event-relations", "542920"], { items: [{ related_event_db_id: 542921, related_event_id: 4624, related_time_utc: "2026-09-10T12:00:01Z", confidence: 1, relation_origin: "stored", reason: "Сохранённая связь." }] });
  client.setQueryData(["event-entities", "542920"], { items: [{ id: 5632, display_name: "CORP\\analyst", natural_key: "account:5632", type: "account", link_role: "target", confidence: 1 }] });
  const root = createRootRoute();
  const event = createRoute({ getParentRoute: () => root, path: "/events/$eventId", component: EventCardPage });
  const investigations = createRoute({ getParentRoute: () => root, path: "/investigations", component: () => null });
  const router = createRouter({ routeTree: root.addChildren([event, investigations]), basepath: "/app",
    history: createMemoryHistory({ initialEntries: ["/app/events/542920?entity_id=5632&scope=important&time_from=2026-09-10T12%3A00%3A00.123001Z&time_to=2026-09-10T12%3A00%3A00.123999Z&timezone=Asia%2FNovosibirsk"] }) });
  const globalScope = globalThis as unknown as { window?: { location: { href: string; search: string; pathname: string } } };
  const hadWindow = Object.hasOwn(globalScope, "window");
  const previousWindow = globalScope.window;
  globalScope.window = { location: {
    href: "http://localhost/app/events/542920?entity_id=5632&scope=important&time_from=2026-09-10T12%3A00%3A00.123001Z&time_to=2026-09-10T12%3A00%3A00.123999Z&timezone=Asia%2FNovosibirsk",
    search: "?entity_id=5632&scope=important&time_from=2026-09-10T12%3A00%3A00.123001Z&time_to=2026-09-10T12%3A00%3A00.123999Z&timezone=Asia%2FNovosibirsk", pathname: "/app/events/542920",
  } };
  try {
    await router.load();
    const html = renderToStaticMarkup(<QueryClientProvider client={client}><RouterProvider router={router} /></QueryClientProvider>);
    const href = html.match(/href="([^"]+)"[^>]*>Открыть контекст события</)?.[1];
    expect(href).toBeDefined();
    const url = new URL(href!.replaceAll("&amp;", "&"), "http://localhost");
    expect(Object.fromEntries(url.searchParams)).toEqual({ event_db_id: "542920", entity_id: "5632", q: "—", scope: "important", time_from: "2026-09-10T12:00:00.123001Z", time_to: "2026-09-10T12:00:00.123999Z", timezone: "Asia/Novosibirsk" });
    expect(html).toContain("Класс каталога: низкий");
    expect(html).not.toContain("Риск ИБ: low");
    expect(html).not.toContain("Уверенность: unknown");
    const entityHref = html.match(/href="([^"]+)"[^>]*>CORP\\analyst</)?.[1];
    expect(entityHref).toBeDefined();
    const entityUrl = new URL(entityHref!.replaceAll("&amp;", "&"), "http://localhost");
    expect(entityUrl.pathname).toBe("/app/entities/5632");
    expect(Object.fromEntries(entityUrl.searchParams)).toEqual({
      event_db_id: "542920",
      entity_id: "5632",
      scope: "important",
      time_from: "2026-09-10T12:00:00.123001Z",
      time_to: "2026-09-10T12:00:00.123999Z",
      timezone: "Asia/Novosibirsk",
      return_to: "/app/events/542920?entity_id=5632&scope=important&time_from=2026-09-10T12%3A00%3A00.123001Z&time_to=2026-09-10T12%3A00%3A00.123999Z&timezone=Asia%2FNovosibirsk",
    });
    const relatedHref = html.match(/href="([^"]+)"[^>]*>Event 4624 · DB 542921</)?.[1];
    expect(relatedHref).toBeDefined();
    const relatedUrl = new URL(relatedHref!.replaceAll("&amp;", "&"), "http://localhost");
    expect(relatedUrl.pathname).toBe("/app/events/542921");
    expect(Object.fromEntries(relatedUrl.searchParams)).toEqual({ event_db_id: "542921", entity_id: "5632", scope: "important", time_from: "2026-09-10T12:00:00.123001Z", time_to: "2026-09-10T12:00:00.123999Z", timezone: "Asia/Novosibirsk" });
  } finally {
    if (hadWindow) globalScope.window = previousWindow;
    else Reflect.deleteProperty(globalScope, "window");
  }
});
