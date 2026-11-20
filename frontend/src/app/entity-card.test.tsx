// @vitest-environment jsdom
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { afterEach, expect, it, vi } from "vitest";
import type { EntityWorkspaceDetail, V4ObjectDetail } from "../api/client";
import { EntityCardPage, objectRouteRedirect, sectionResultState } from "./entity-card";
import { entityWorkspaceApiParameters } from "./investigation-context";
import { formatDateTime } from "../shared/date-time";
import { localeRuntime, setLocale, t } from "../i18n";
import { ru } from "../i18n/ru";

afterEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("ru"); vi.restoreAllMocks(); });

vi.mock("./account-watch", () => ({ AccountWatch: ({ entityId }: { entityId: number }) => <div data-watch-entity={entityId}/> }));

const SEARCH = "time_from=2026-09-10&time_to=2026-09-11&timezone=UTC";

const workspace = (patch: Partial<EntityWorkspaceDetail> = {}): EntityWorkspaceDetail => ({
  api_version: "v1",
  entity: { id: 7, type: "ad_user", natural_key: "S-1-5-21-7", display_name: "CORP\analyst", first_seen_utc: "2026-09-01T08:00:00Z", last_seen_utc: "2026-09-10T12:00:00Z" },
  current_states: [], current_states_state: "available", ad_context_state: "available",
  ad_context: { resolution: "not_found", items: [], returned_count: 0, bounded: true },
  events: [], events_state: "available", events_scope_filtered: false,
  security_actions_state: "available", security_actions: [], semantic_relations_state: "available", semantic_relations: [],
  has_more: false, limits: { events: 50 },
  ...patch,
} as EntityWorkspaceDetail);

const object: V4ObjectDetail = {
  api_version: "v4", state: "available",
  object: { object_type: "ad_user", object_id: "7", display_name: "CORP\analyst", latest_state: { status: "enabled" } },
  identity_links: [], identity_contract: "employee_and_account_are_distinct_objects",
  tabs: [{ id: "overview", label: "Обзор", available: true }, { id: "groups", label: "Членство", available: true }, { id: "findings", label: "Находки", available: false }],
  current_states: [], directory_context: { items: [] }, findings: [],
  events: [], events_state: "available", has_more_events: false, actions: [],
  provenance: [{ source: "AD Context", observed_at_utc: "2026-09-10T12:00:00Z", freshness: "observed" }], limitations: ["Снимок и событие являются разными типами факта"],
};

async function render(tab: string, data: EntityWorkspaceDetail, v4: V4ObjectDetail | null = object) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["entity", "7", entityWorkspaceApiParameters(SEARCH, 50).toString()], data);
  if (v4) client.setQueryData(["v4", "object", "entity", "7"], v4);
  const root = createRootRoute();
  const route = createRoute({ getParentRoute: () => root, path: "/entities/$entityId", component: EntityCardPage });
  const router = createRouter({ routeTree: root.addChildren([route]), basepath: "/app", history: createMemoryHistory({ initialEntries: [`/app/entities/7?${SEARCH}&tab=${tab}`] }) });
  await router.load();
  return renderToStaticMarkup(<QueryClientProvider client={client}><RouterProvider router={router}/></QueryClientProvider>);
}

it("renders the header and only the tabs the server marks available", async () => {
  const html = await render("overview", workspace());
  expect(html).toContain("CORP\analyst");
  expect(html).toContain("Учётная запись AD");
  expect(html).toContain("AD Context");
  expect(html).toContain("Снимок и событие являются разными типами факта");
  const tabs = [...html.matchAll(/role="tab"[^>]*>([^<]+)</g)].map((match) => match[1]);
  expect(tabs).toEqual(["Обзор", "Членство в группах", "События", "Действия безопасности", "VPN-сессии"]);
});

it.each(["ru", "en"] as const)("localizes entity tabs and known warnings while preserving unknown source text in %s", async (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  const warnings = ["entities.fixed.snapshot_event", "entities.fixed.missing_value", "entities.fixed.eventsTimeout", "entities.fixed.exactPolicy", "entities.fixed.resourcePolicy", "entities.fixed.identityPolicy", "entities.fixed.noObservation"] as const;
  const rawWarning = "Неизвестное исходное ограничение";
  const html = await render("overview", workspace(), { ...object, limitations: [...warnings.map((key) => ru[key]), rawWarning] });
  const tabs = [...html.matchAll(/role="tab"[^>]*>([^<]+)</g)].map((match) => match[1]);
  expect(tabs.length).toBe(5);
  if (locale === "en") expect(tabs.join(" ")).not.toMatch(/[А-Яа-яЁё]/);
  for (const key of warnings) expect(html).toContain(t(key));
  expect(html).toContain(rawWarning);
  if (locale === "en") expect(html).not.toContain(ru["entities.fixed.snapshot_event"]);
  expect(html).toContain("AD Context");
});

it("mounts watch controls for the exact AD account card only", async () => {
  expect(await render("overview", workspace())).toContain('data-watch-entity="7"');
  expect(await render("overview", workspace({ entity: { ...workspace().entity, type: "ad_group" } }),
    { ...object, object: { ...object.object, object_type: "ad_group" } })).not.toContain("data-watch-entity");
});

it("never renders an unavailable or bounded section as an empty one", async () => {
  const events = await render("events", workspace({ events_state: "temporarily_unavailable" }));
  expect(events).toContain('data-state="unavailable"');
  expect(events).not.toContain('data-state="empty"');
  const security = await render("security", workspace({ security_actions_state: "time_bounds_required", semantic_relations_state: "time_bounds_required" }), null);
  expect(security.match(/data-state="partial"/g)).toHaveLength(2);
  expect(security).not.toContain('data-state="empty"');
  const vpn = await render("vpn", workspace());
  expect(vpn).not.toContain('data-state="empty"');
  const forbidden = await render("events", workspace({ events_state: "forbidden" }));
  expect(forbidden).toContain('data-state="denied"');
});

it("keeps the exact evidence link of an event row", async () => {
  const html = await render("events", workspace({ events: [{ event_db_id: 517550, event_id: 4624, time_utc: "2026-09-10T12:00:00Z", link_role: "target", confidence: 1 }] }));
  expect(html).toMatch(/href="\/app\/events\/517550\?[^"]*entity_id=7[^"]*">DB 517550</);
  expect(html).toContain("12:00:00");
});

it("maps section states to honest result states", () => {
  expect(sectionResultState("available").state).toBe("ok");
  expect(sectionResultState("not_authorized").state).toBe("denied");
  expect(sectionResultState("schema_unavailable").state).toBe("unavailable");
  expect(sectionResultState("something_new").state).toBe("unavailable");
});

it("redirects the retired object address to the entity card and keeps the search", () => {
  expect(objectRouteRedirect("5", { tab: "groups" })).toEqual({ to: "/entities/$entityId", params: { entityId: "5" }, search: { tab: "groups" } });
});

it("shows a concise profile and keeps identifiers in closed technical details", async () => {
  const html = await render("overview", workspace(), {
    ...object, directory_context: { items: [{ context_kind: "entity", attributes: {
      display_name: "Example account", sam_account_name: "test-account", enabled: true,
      object_guid: "00000000-0000-4000-8000-000000000001", email: "user@example.invalid", mail: "user@example.invalid",
    } }] },
  });
  const profile = html.slice(html.indexOf('aria-label="Профиль"'), html.indexOf('</section>', html.indexOf('aria-label="Профиль"')));
  const summary = profile.slice(0, profile.indexOf("<details>"));
  expect(summary).toContain("Example account");
  expect(summary).toContain("Включено");
  expect(summary).not.toContain("object_guid");
  expect(summary).not.toContain("user@example.invalid");
  expect(profile).toContain("<details><summary>Технические атрибуты</summary>");
  expect(profile).toContain("object_guid");
  expect(profile.match(/user@example.invalid/g)).toHaveLength(1);
});

it.each([
  { status: "partial", exact: "2026-09-01T10:00:00Z", timestamp: "2026-09-05T10:00:00Z", successful: 2, discovered: 3, date: "2026-09-05T10:00:00Z", note: "по опрошенным DC 2 из 3" },
  { status: "partial", exact: "2026-09-06T10:00:00Z", timestamp: "2026-09-05T10:00:00Z", successful: 1, discovered: 3, date: "2026-09-06T10:00:00Z", note: "по опрошенным DC 1 из 3" },
  { status: "observed", exact: "2026-09-01T10:00:00Z", timestamp: "2026-09-05T10:00:00Z", successful: 3, discovered: 3, date: "2026-09-01T10:00:00Z", note: "" },
  { status: "observed", exact: "2026-09-01T10:00:00Z", timestamp: null, successful: 2, discovered: 3, date: "2026-09-01T10:00:00Z", note: "по опрошенным DC 2 из 3" },
  { status: "partial", exact: "2026-09-01T10:00:00Z", timestamp: null, successful: null, discovered: null, date: "2026-09-01T10:00:00Z", note: "Опрос контроллеров домена неполный" },
  { status: "partial", exact: null, timestamp: null, successful: 2, discovered: 3, date: null, note: "по опрошенным DC 2 из 3" },
])("shows last activity with honest DC coverage: $status, $successful/$discovered, $date", async ({ status, exact, timestamp, successful, discovered, date, note }) => {
  const html = await render("overview", workspace(), {
    ...object, directory_context: { items: [{ context_kind: "entity", attributes: {
      exact_last_logon_utc: exact, last_logon_timestamp_utc: timestamp,
      exact_last_logon_status: status, exact_last_logon_successful_dc_count: successful,
      exact_last_logon_discovered_dc_count: discovered,
    } }] },
  });
  const start = html.indexOf('aria-label="Профиль"');
  const summary = html.slice(start, html.indexOf("<details>", start));
  const expectedDate = date ? formatDateTime(date, "UTC", { seconds: true }) : "—";
  expect(summary).toContain(`<dd>${expectedDate}${note ? ` · ${note}` : ""}</dd>`);
  expect(summary).not.toContain("exact_last_logon");
  expect(summary).not.toContain("partial");
  expect(summary).not.toContain("observed");
  if (!note) expect(summary).not.toContain("опрошенным DC");
});

it("shows neutral event and attribution placeholders for withheld fields", async () => {
  for (const event of [
    { event_db_id: 517550 },
    { event_db_id: 517550, event_id: null, link_role: null, confidence: null },
  ]) {
    const html = await render("events", workspace({ events: [event] }));
    expect(html).not.toMatch(/Event ID (null|undefined)/);
    expect(html).not.toContain("NaN");
    expect(html).not.toContain("0%");
    expect(html).toContain(t("entities.timeline.eventFallback"));
    expect(html).toContain(t("entities.section.events.notDetermined"));
    expect(html).toContain(t("entities.unknownCapital"));
    expect(html).toContain("DB 517550");
  }
});

it("preserves an observed zero confidence instead of treating it as withheld", async () => {
  const html = await render("events", workspace({ events: [
    { event_db_id: 517550, event_id: 4624, link_role: "actor", confidence: 0 },
  ] }));
  expect(html).toContain("0%");
  expect(html).toContain("Event ID 4624");
  expect(html).toContain("actor");
});
