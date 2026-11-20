// @vitest-environment jsdom
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { afterEach, expect, it, vi } from "vitest";
import { ObjectsPage, entitiesRouteRedirect } from "./objects";
import { localeRuntime, setLocale, t } from "../i18n";

afterEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("ru"); vi.restoreAllMocks(); });

it.each(["ru", "en"] as const)("localizes entity-search labels and preserves a source name in %s", async (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  const html = await render("/app/search?q=fixture", (client) => {
    client.setQueryData(["entity-types"], { type_counts: TYPE_COUNTS, items: [], has_more: false, limits: {} });
    client.setQueryData(["entities", "fixture", "участники", []], {
      api_version: "v1", query: "fixture", state: "ok", has_more: false, type_counts: TYPE_COUNTS, limits: { items: 50 },
      items: [{ id: 5632, type: "ad_user", natural_key: "account:5632", display_name: "Исходное имя", latest_state: { status: "enabled", evidence_event_db_id: 517548 } }],
    });
  });
  expect(html).toContain(t("entities.objects.col.entity"));
  expect(html).toContain(t("entities.objects.col.latestState"));
  expect(html).toContain("Исходное имя");
  if (locale === "en") expect(html.replaceAll("Исходное имя", "")).not.toMatch(/[А-Яа-яЁё]/);
});

const TYPE_COUNTS = [{ entity_type: "ad_user", count: 3 }];

async function render(url: string, seed: (client: QueryClient) => void) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  seed(client);
  const root = createRootRoute();
  const route = createRoute({ getParentRoute: () => root, path: "/search", component: ObjectsPage });
  const entity = createRoute({ getParentRoute: () => root, path: "/entities/$entityId", component: () => null });
  const events = createRoute({ getParentRoute: () => root, path: "/events/$eventId", component: () => null });
  const router = createRouter({ routeTree: root.addChildren([route, entity, events]), basepath: "/app", history: createMemoryHistory({ initialEntries: [url] }) });
  await router.load();
  return renderToStaticMarkup(<QueryClientProvider client={client}><RouterProvider router={router}/></QueryClientProvider>);
}

it("renders entity search rows that link to the entity card", async () => {
  const html = await render("/app/search?q=analyst", (client) => {
    client.setQueryData(["entity-types"], { type_counts: TYPE_COUNTS, items: [], has_more: false, limits: {} });
    client.setQueryData(["entities", "analyst", "участники", []], {
      api_version: "v1", query: "analyst", state: "ok", has_more: false, type_counts: TYPE_COUNTS, limits: { items: 50 },
      items: [{ id: 5632, type: "ad_user", natural_key: "account:5632", display_name: "CORP\\analyst", first_seen_utc: "2026-09-01T08:00:00Z", last_seen_utc: "2026-09-10T12:00:00Z", latest_state: { status: "enabled", evidence_event_db_id: 517548 } }],
    });
  });
  expect(html).toMatch(/href="\/app\/entities\/5632"[^>]*>CORP\\analyst</);
  expect(html).toMatch(/href="\/app\/events\/517548"/);
  expect(html).toContain("Глобальный поиск");
  expect(html).toMatch(/<details[^>]*>[\s\S]*account:5632[\s\S]*<\/details>/);
  expect(html).not.toMatch(/<small>account:5632<\/small>/);
});

it("renders registry rows that link to /entities/<id> and keeps a hidden scope honest", async () => {
  const html = await render("/app/search?source=registry&q=srv", (client) => {
    client.setQueryData(["v4", "objects", "srv", ""], {
      api_version: "v4", query: "srv", state: "available", has_more: false, scope_filtered: true, limits: {},
      items: [{ object_type: "computer", object_id: "9", display_name: "SRV-01", natural_key: "srv-01", source: "AD snapshot", freshness: "observed" }],
    });
  });
  expect(html).toMatch(/href="\/app\/entities\/9"[^>]*>SRV-01</);
  expect(html).toMatch(/<details[^>]*>[\s\S]*srv-01[\s\S]*<\/details>/);
  expect(html).toContain('data-state="partial"');
});

it("never renders an unavailable registry section as an empty list", async () => {
  const html = await render("/app/search?source=registry", (client) => {
    client.setQueryData(["v4", "objects", "", ""], { api_version: "v4", query: "", state: "temporarily_unavailable", has_more: false, limits: {}, items: [] });
  });
  expect(html).toContain('data-state="unavailable"');
  expect(html).not.toContain('data-state="empty"');
});

it("redirects the retired entity list to global search with the same search", () => {
  expect(entitiesRouteRedirect({ q: "abc" })).toEqual({ to: "/search", search: { q: "abc" }, replace: true });
});
