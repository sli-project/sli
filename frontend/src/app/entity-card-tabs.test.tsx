import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { expect, it } from "vitest";
import type { EntityWorkspaceDetail, V4ObjectDetail } from "../api/client";
import { EntityCardPage, entityProfileFields, sectionResultState } from "./entity-card";
import { entityWorkspaceApiParameters } from "./investigation-context";

const SEARCH = "time_from=2026-09-10&time_to=2026-09-11&timezone=UTC";

const workspace = (patch: Partial<EntityWorkspaceDetail> = {}): EntityWorkspaceDetail => ({
  api_version: "v1",
  entity: { id: 7, type: "ad_user", natural_key: "S-1-5-21-7", display_name: "Demo User", first_seen_utc: "2026-09-01T08:00:00Z", last_seen_utc: "2026-09-10T12:00:00Z" },
  current_states: [], current_states_state: "available", ad_context_state: "available",
  ad_context: { resolution: "not_found", items: [], returned_count: 0, bounded: true },
  events: [], events_state: "available", events_scope_filtered: false,
  security_actions_state: "available", security_actions: [], semantic_relations_state: "available", semantic_relations: [],
  has_more: false, limits: { events: 50 },
  ...patch,
} as EntityWorkspaceDetail);

const allTabs = ["overview", "groups", "privileges", "states", "findings", "technical"].map((id) => ({ id, label: id, available: true }));
const relation = (section: string, id: number, name: string) => ({
  context_evidence_id: id, context_kind: "relation", source_section: section, related_entity_id: id, related_display_name: name,
  current: true, observed_at_utc: "2026-09-10T12:00:00Z", attributes: { source_section: section, membership_type: "direct" },
});
const v4 = (items: Array<Record<string, unknown>>, patch: Partial<V4ObjectDetail> = {}, objectType = "ad_user"): V4ObjectDetail => ({
  api_version: "v4", state: "available",
  object: { object_type: objectType, object_id: "7", display_name: "Demo User", latest_state: null },
  identity_links: [], identity_contract: "employee_and_account_are_distinct_objects",
  tabs: allTabs, current_states: [], directory_context: { items }, findings: [],
  events: [], events_state: "available", has_more_events: false, actions: [], provenance: [], limitations: [],
  ...patch,
});

async function render(tab: string, data: EntityWorkspaceDetail, object: V4ObjectDetail, search = SEARCH) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["entity", "7", entityWorkspaceApiParameters(search, 50).toString()], data);
  client.setQueryData(["v4", "object", "entity", "7"], object);
  const root = createRootRoute();
  const route = createRoute({ getParentRoute: () => root, path: "/entities/$entityId", component: EntityCardPage });
  const router = createRouter({ routeTree: root.addChildren([route]), basepath: "/app", history: createMemoryHistory({ initialEntries: [`/app/entities/7?${search ? `${search}&` : ""}tab=${tab}`] }) });
  await router.load();
  return renderToStaticMarkup(<QueryClientProvider client={client}><RouterProvider router={router}/></QueryClientProvider>);
}

const tabLabels = (html: string) => [...html.matchAll(/role="tab"[^>]*>([^<]+)</g)].map((match) => match[1]);

it("a reader that found nothing is an empty section, not an outage", async () => {
  expect(sectionResultState("empty").state).toBe("ok");
  expect(sectionResultState("empty_unverified").state).toBe("ok");
  expect(sectionResultState("not_collected").state).toBe("unavailable");
  const html = await render("security", workspace({ security_actions_state: "empty_unverified", semantic_relations_state: "empty" }), v4([]));
  expect(html.match(/data-state="empty"/g)).toHaveLength(2);
  expect(html).not.toContain('data-state="unavailable"');
});

it("groups tab lists the memberships the server sends in their real shape", async () => {
  const html = await render("groups", workspace(), v4([relation("vpn_membership", 375, "VPN Users"), relation("privileged_membership", 387, "Admins")]));
  expect(html).toContain("VPN Users");
  expect(html).toContain("Admins");
  expect(html).toContain("Контекст AD · VPN-группы");
  expect(html).not.toContain('data-state="empty"');
});

it("groups and privileges tabs give a specific empty state, distinguishing a missing AD context", async () => {
  const noContext = await render("groups", workspace(), v4([]));
  expect(noContext).toContain('data-state="empty"');
  expect(noContext).toContain("AD-контекст для этого объекта не получен");
  expect(noContext).not.toContain("Измените фильтры или период");
  const noGroups = await render("groups", workspace(), v4([{ context_kind: "entity", attributes: { display_name: "x" } }]));
  expect(noGroups).toContain("связей членства в группах в нём нет");
  expect(noGroups).not.toContain("Измените фильтры или период");
  const noPrivileges = await render("privileges", workspace(), v4([relation("vpn_membership", 375, "VPN Users")]));
  expect(noPrivileges).toContain("нет связей с привилегированными группами");
});

it("privileges tab shows only privileged memberships", async () => {
  const html = await render("privileges", workspace(), v4([relation("vpn_membership", 375, "VPN Users"), relation("privileged_membership", 387, "Admins")]));
  expect(html).toContain("Admins");
  expect(html).not.toContain("VPN Users");
});

it("states tab shows confirmed states and otherwise says what builds them", async () => {
  const state = { state_type: "account.access", status: "disabled", projection_status: "normal" as const, observed_at_utc: "2026-09-10T12:00:00Z", evidence_event_db_id: 99, rule_id: "r1", rule_version: "1", summary: "Учётная запись отключена" };
  const filled = await render("states", workspace({ current_states: [state] }), v4([]));
  expect(filled).toContain("Учётная запись отключена");
  const empty = await render("states", workspace(), v4([]));
  expect(empty).toContain('data-state="empty"');
  expect(empty).toContain("строятся правилами из событий");
});

it("findings tab shows linked findings and otherwise explains how findings are linked", async () => {
  const filled = await render("findings", workspace(), v4([], { findings: [{ id: 5, title: "Подозрительный вход", severity: "high", status: "open", summary: "почему", evidence_event_id: 12 }] }));
  expect(filled).toContain("Подозрительный вход");
  const empty = await render("findings", workspace(), v4([]));
  expect(empty).toContain("только по точной идентичности");
});

it("technical tab lists the context records", async () => {
  const html = await render("technical", workspace(), v4([relation("vpn_membership", 375, "VPN Users")]));
  expect(html).toContain("vpn_membership");
});

it("security and VPN tabs offer a period instead of a dead-end request to choose one", async () => {
  const quiet = workspace({ security_actions_state: "time_bounds_required", semantic_relations_state: "time_bounds_required" });
  const vpn = await render("vpn", quiet, v4([]), "");
  expect(vpn).toContain("Период вкладок");
  expect(vpn).not.toContain("выберите полный период");
  expect(vpn).toContain('value="2026-09-10"');
  const security = await render("security", quiet, v4([]), "");
  expect(security).toContain("Период вкладок");
});

it("hides tabs that can never have data for the entity type", async () => {
  const group = await render("overview", workspace({ entity: { ...workspace().entity, type: "ad_group" } }), v4([], {}, "ad_group"));
  expect(tabLabels(group)).toContain("Членство в группах");
  expect(tabLabels(group)).not.toContain("VPN-сессии");
  const gpo = await render("overview", workspace({ entity: { ...workspace().entity, type: "gpo" } }), v4([], {}, "gpo"));
  expect(tabLabels(gpo)).not.toContain("Членство в группах");
  expect(tabLabels(gpo)).not.toContain("Доступ и привилегии");
});

it("selects each profile attribute by current version and last observation, regardless of input order", () => {
  const items = [
    { context_kind: "entity", current: false, observed_at_utc: "2026-09-12T12:00:00Z", attributes: { enabled: true, department: "historical", title: "latest title" } },
    { context_kind: "entity", current: true, observed_at_utc: "2026-09-01T12:00:00Z", last_observed_at_utc: "2026-09-11T12:00:00Z", attributes: { attributes: { enabled: false, department: null } } },
    { context_kind: "entity", current: true, observed_at_utc: "2026-09-10T12:00:00Z", attributes: { enabled: true, department: "older" } },
    { context_kind: "entity", current: false, observed_at_utc: "2026-09-09T12:00:00Z", attributes: { title: "old title", record_key: "old-record" } },
    { context_kind: "relation", current: true, observed_at_utc: "2026-09-13T12:00:00Z", attributes: { title: "relation title" } },
  ];
  for (const order of [items, [...items].reverse()]) {
    const fields = entityProfileFields(order);
    expect(fields.get("enabled")?.value).toBe(false);
    expect(fields.get("department")?.value).toBeNull();
    expect(fields.get("title")?.value).toBe("latest title");
    expect(fields.get("enabled")?.observedAt).toBe("2026-09-11T12:00:00Z");
    expect(fields.has("record_key")).toBe(false);
  }
});

it("falls back to the latest historical attributes, breaking time ties by evidence id", () => {
  const fields = entityProfileFields([
    { context_kind: "entity", current: false, context_evidence_id: 3, observed_at_utc: "2026-09-10T12:00:00Z", attributes: { enabled: false, password_never_expires: false } },
    { context_kind: "entity", current: false, context_evidence_id: 2, observed_at_utc: "2026-09-10T12:00:00Z", attributes: { enabled: true } },
    { context_kind: "entity", current: false, observed_at_utc: "invalid", attributes: { enabled: true, password_never_expires: true } },
    { context_kind: "entity", attributes: ["invalid"] },
  ]);
  expect(fields.get("enabled")?.value).toBe(false);
  expect(fields.get("password_never_expires")?.value).toBe(false);
  expect(entityProfileFields([]).size).toBe(0);
});

it("shows the selected attribute's observation date and source, including historical fallback", async () => {
  const html = await render("overview", workspace(), v4([
    { context_kind: "entity", current: true, observed_at_utc: "2026-09-01T12:00:00Z", last_observed_at_utc: "2026-09-11T12:00:00Z", source_pack_id: "test-pack", source_section: "directory_accounts", context_evidence_id: 5, attributes: { enabled: false } },
    { context_kind: "entity", current: false, observed_at_utc: "2026-09-09T12:00:00Z", source_pack_id: "test-pack", source_section: "directory_accounts", context_evidence_id: 4, attributes: { enabled: true, title: "historical title" } },
  ]));
  expect(html).toContain("<dd>Отключено</dd>");
  expect(html).not.toContain("<dd>Включено</dd>");
  expect(html).toContain("Текущая · Наблюдение: 11.09.2026, 12:00:00 · Источник: test-pack · directory_accounts · #5");
  expect(html).toContain("Историческая · Наблюдение: 09.09.2026, 12:00:00 · Источник: test-pack · directory_accounts · #4");
});
