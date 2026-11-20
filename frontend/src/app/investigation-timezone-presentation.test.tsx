import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { expect, it } from "vitest";
import { EventCardPage } from "./event-card";
import { InvestigationWorkspacePage } from "./investigation-workspace";
import { investigationContext, investigationQueryKey } from "./investigation-context";

it("investigation history renders the URL UTC context instead of the global Novosibirsk setting", async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  const search = "event_db_id=517548&scope=all&timezone=UTC";
  client.setQueryData([...investigationQueryKey(investigationContext(new URLSearchParams(search))), "pages"], { pageParams: [null], pages: [{
    state: "available", query: "", scope: "all", findings: [], next_checks: [], limits: {},
    timeline: [{ event_db_id: 517548, event_id: 4624, time_utc: "2026-09-10T22:35:00Z", title: "Вход", server: null, actor: null, target: null, channel: null, severity: "info", catalogued: true }],
    summary: { events_returned: 1, has_more: false, attention_level: "unknown", story: "", why_it_matters: "" },
  }] });
  client.setQueryData(["investigation-cases"], { items: [] });
  client.setQueryData(["bootstrap"], {});
  client.setQueryData(["event-relations", 517548], { items: [] });
  const root = createRootRoute();
  const investigations = createRoute({ getParentRoute: () => root, path: "/investigations", component: InvestigationWorkspacePage });
  const router = createRouter({ routeTree: root.addChildren([investigations]), basepath: "/app", history: createMemoryHistory({ initialEntries: [`/app/investigations?${search}`] }) });
  await router.load();
  const html = renderToStaticMarkup(<QueryClientProvider client={client}><RouterProvider router={router} /></QueryClientProvider>);
  expect(html).toContain("22:35:00");
  expect(html).not.toContain("05:35:00");
});

it("event detail shows an unavailable requested timezone instead of silently using the global setting", async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["bootstrap"], { effective_role: "viewer" });
  client.setQueryData(["event", "517548"], { item: { event_db_id: 517548, event_id: 4624, time_created_utc: "2026-09-10T22:35:00Z", subject: null, target: null, server: null, source: null, provider_name: null, event_record_id: null, event_data: {}, message_text: null } });
  client.setQueryData(["event-relations", "517548"], { items: [] });
  client.setQueryData(["event-entities", "517548"], { items: [] });
  const root = createRootRoute();
  const event = createRoute({ getParentRoute: () => root, path: "/events/$eventId", component: EventCardPage });
  const router = createRouter({ routeTree: root.addChildren([event]), basepath: "/app", history: createMemoryHistory({ initialEntries: ["/app/events/517548?timezone=Unknown%2FZone"] }) });
  const globalScope = globalThis as unknown as { window?: { location: { href: string; search: string; pathname: string } } };
  const previousWindow = globalScope.window;
  globalScope.window = { location: { href: "http://localhost/app/events/517548?timezone=Unknown%2FZone", search: "?timezone=Unknown%2FZone", pathname: "/app/events/517548" } };
  try {
    await router.load();
    const html = renderToStaticMarkup(<QueryClientProvider client={client}><RouterProvider router={router} /></QueryClientProvider>);
    expect(html).toContain("Часовой пояс Unknown/Zone недоступен");
    expect(html).not.toContain("05:35:00");
  } finally {
    if (previousWindow) globalScope.window = previousWindow;
    else Reflect.deleteProperty(globalScope, "window");
  }
});

it("investigation history rejects an unavailable URL timezone before a workspace request", async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["bootstrap"], {});
  const root = createRootRoute();
  const investigations = createRoute({ getParentRoute: () => root, path: "/investigations", component: InvestigationWorkspacePage });
  const router = createRouter({ routeTree: root.addChildren([investigations]), basepath: "/app", history: createMemoryHistory({ initialEntries: ["/app/investigations?event_db_id=517548&timezone=Unknown%2FZone"] }) });
  await router.load();
  const html = renderToStaticMarkup(<QueryClientProvider client={client}><RouterProvider router={router} /></QueryClientProvider>);
  expect(html).toContain("Контекст расследования не принят");
  expect(html).toContain("invalid_timezone");
  expect(html).not.toContain("Строим ограниченную историю");
});
