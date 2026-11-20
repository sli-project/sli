import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { expect, it } from "vitest";
import { EntityCardPage } from "./entity-card";
import { InvestigationWorkspacePage } from "./investigation-workspace";
import { entityWorkspaceApiParameters, investigationContext, investigationQueryKey } from "./investigation-context";

it("entity card investigates its exact identity and carries the selected interval", async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  const entitySearch = "scope=important&time_from=2026-09-10&time_to=2026-09-11&timezone=UTC&return_to=%2Fapp%2Fsecurity-events-report%3Fcategory%3Daccount_lock";
  client.setQueryData(["entity", "42", entityWorkspaceApiParameters(entitySearch, 50).toString()], {
    entity: { id: 42, type: "user", natural_key: "not-an-identity-proof", display_name: "Same name" },
    current_states: [], current_states_state: "available", ad_context_state: "available",
    ad_context: { resolution: "not_found", items: [], returned_count: 0 },
    events: [{ event_db_id: 517550, event_id: 4624, time_utc: "2026-09-10T12:00:00Z", link_role: "target", confidence: 1, actor: null, target: null, server: null, channel: null, provider_name: null }], events_state: "available", has_more: false, limits: { events: 50 },
  });
  const root = createRootRoute();
  const entity = createRoute({ getParentRoute: () => root, path: "/entities/$entityId", component: EntityCardPage });
  const entities = createRoute({ getParentRoute: () => root, path: "/entities", component: () => null });
  const router = createRouter({ routeTree: root.addChildren([entity, entities]), basepath: "/app",
    history: createMemoryHistory({ initialEntries: [`/app/entities/42?${entitySearch}&tab=events`] }) });
  await router.load();
  const html = renderToStaticMarkup(<QueryClientProvider client={client}><RouterProvider router={router} /></QueryClientProvider>);
  const href = html.match(/href="([^"]+)"[^>]*>Расследовать сущность</)?.[1];
  expect(href).toBeDefined();
  const url = new URL(href!.replaceAll("&amp;", "&"), "http://localhost");
  expect(Object.fromEntries(url.searchParams)).toEqual({ entity_id: "42", scope: "important", time_from: "2026-09-10", time_to: "2026-09-11", timezone: "UTC", return_to: "/app/security-events-report?category=account_lock" });
  const evidenceHref = html.match(/href="([^"]+)"[^>]*>DB 517550</)?.[1];
  expect(evidenceHref).toBeDefined();
  const evidenceUrl = new URL(evidenceHref!.replaceAll("&amp;", "&"), "http://localhost");
  expect(evidenceUrl.pathname).toBe("/app/events/517550");
  expect(Object.fromEntries(evidenceUrl.searchParams)).toEqual({ event_db_id: "517550", entity_id: "42", scope: "important", time_from: "2026-09-10", time_to: "2026-09-11", timezone: "UTC", return_to: "/app/security-events-report?category=account_lock" });
  expect(html).toContain("12:00:00");
  expect(html).not.toContain("19:00:00");
  expect(html).toContain('href="/app/security-events-report?category=account_lock">Назад</a>');
  expect(evidenceUrl.searchParams.get("return_to")).toBe("/app/security-events-report?category=account_lock");
});

it("entity card renders shared action roles, outcome, transition and saved relation explanation without disclosing denied rows", async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  const entitySearch = "time_from=2026-09-10T12%3A00%3A00.123001Z&time_to=2026-09-10T12%3A00%3A00.123999Z&timezone=UTC";
  client.setQueryData(["entity", "42", entityWorkspaceApiParameters(entitySearch, 50).toString()], {
    entity: { id: 42, type: "user", natural_key: "S-1-5-21-42", display_name: "Affected" },
    current_states: [], current_states_state: "available", ad_context_state: "available",
    ad_context: { resolution: "not_found", items: [], returned_count: 0 },
    events: [], events_state: "available", has_more: false, limits: { events: 50 },
    security_actions_state: "available",
    security_actions: [{
      event_db_id: 517548, event_id: 4722, event_family: "account_lifecycle",
      time_created_utc: "2026-09-10T12:00:00.123456Z",
      actor: { state: "observed", sid: "S-1-5-21-actor", name: "operator" },
      affected_account: { state: "observed", sid: "S-1-5-21-42", name: "Affected", entity_id: 42 },
      member: { state: "unknown" }, group: { state: "unknown" },
      source_host: { state: "observed", hostname: "dc01" },
      outcome: { state: "observed", value: "success", basis: "event_id" },
      evidence: { state: "complete", missing_fields: [], event_db_id: 517548, event_record_id: 11 },
      account_change: { change: { kind: "enabled" }, observed_transition: {
        before: { state: "partial", last_observed: { value: "present", event_db_id: 517547, time_created_utc: "2026-09-10T12:00:00.000001Z" }, reason: "intervening_account_state_not_proven" },
        after: { state: "observed", value: "enabled" },
      } },
    }],
    semantic_relations_state: "available",
    semantic_relations: [{ candidate_id: "saved-relation", relation_kind: "authentication.account.unlock_after_lock_observed", explanation: "A lockout observation strictly precedes an unlock observation.", identity_basis: { kind: "exact_domain_account_sid", domain_id: 7, account_sid: "S-1-5-21-42" }, continuation_state: "ambiguous", possible_continuation_count: 2, evidence: [] }],
  });
  const root = createRootRoute();
  const entity = createRoute({ getParentRoute: () => root, path: "/entities/$entityId", component: EntityCardPage });
  const router = createRouter({ routeTree: root.addChildren([entity]), basepath: "/app", history: createMemoryHistory({ initialEntries: [`/app/entities/42?${entitySearch}&tab=security`] }) });
  await router.load();
  const html = renderToStaticMarkup(<QueryClientProvider client={client}><RouterProvider router={router} /></QueryClientProvider>);
  expect(html).toContain("Действия безопасности");
  expect(html).toContain("Учётная запись включена");
  expect(html).toContain("Успешно");
  expect(html).toContain("operator");
  expect(html).toContain("запись создана → включена");
  expect(html).toContain("на основании точного SID учётной записи");
  expect(html).toContain("Совпали домен 7 и точный SID учётной записи S-1-5-21-42.");
  expect(html).toContain("конкретное продолжение не установлено");
  const actionEvidenceHref = html.match(/href="([^"]+)"[^>]*>DB 517548</)?.[1];
  expect(actionEvidenceHref).toBeDefined();
  const actionEvidenceUrl = new URL(actionEvidenceHref!.replaceAll("&amp;", "&"), "http://localhost");
  expect(actionEvidenceUrl.pathname).toBe("/app/events/517548");
  expect(Object.fromEntries(actionEvidenceUrl.searchParams)).toEqual({
    event_db_id: "517548",
    entity_id: "42",
    scope: "all",
    time_from: "2026-09-10T12:00:00.123001Z",
    time_to: "2026-09-10T12:00:00.123999Z",
    timezone: "UTC",
    return_to: "/app/objects",
  });
});

it("entity card keeps denied shared readers distinct from an empty result", async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  const entitySearch = "time_from=2026-09-10&time_to=2026-09-11&timezone=UTC";
  client.setQueryData(["entity", "42", entityWorkspaceApiParameters(entitySearch, 50).toString()], {
    entity: { id: 42, type: "user", natural_key: "S-1-5-21-42", display_name: "Affected" },
    current_states: [], current_states_state: "available", ad_context_state: "available",
    ad_context: { resolution: "not_found", items: [], returned_count: 0 },
    events: [], events_state: "available", has_more: false, limits: { events: 50 },
    security_actions_state: "not_authorized", security_actions: [],
    semantic_relations_state: "not_authorized", semantic_relations: [],
  });
  const root = createRootRoute();
  const entity = createRoute({ getParentRoute: () => root, path: "/entities/$entityId", component: EntityCardPage });
  const router = createRouter({ routeTree: root.addChildren([entity]), basepath: "/app", history: createMemoryHistory({ initialEntries: [`/app/entities/42?${entitySearch}&tab=security`] }) });
  await router.load();
  const html = renderToStaticMarkup(<QueryClientProvider client={client}><RouterProvider router={router} /></QueryClientProvider>);
  expect(html.match(/data-state="denied"/g)).toHaveLength(2);
  expect(html).not.toContain("Сохранённых связей для этой сущности в выбранном периоде нет.");
});

it("investigation opens an exact entity context without requiring a name query", async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  const search = "entity_id=42&scope=all&time_from=2026-09-10&timezone=UTC&return_to=%2Fapp%2Fsecurity-events-report%3Ftab%3Dchains";
  client.setQueryData([...investigationQueryKey(investigationContext(new URLSearchParams(search))), "pages"], { pageParams: [null], pages: [{
    state: "empty", query: "", scope: "all", timeline: [], findings: [], next_checks: [], limits: {},
    summary: { events_returned: 0, has_more: false, attention_level: "unknown", story: "", why_it_matters: "" },
  }] });
  client.setQueryData(["investigation-cases"], { items: [] });
  client.setQueryData(["bootstrap"], {});
  const root = createRootRoute();
  const investigations = createRoute({ getParentRoute: () => root, path: "/investigations", component: InvestigationWorkspacePage });
  const router = createRouter({ routeTree: root.addChildren([investigations]), basepath: "/app",
    history: createMemoryHistory({ initialEntries: [`/app/investigations?${search}`] }) });
  await router.load();
  const html = renderToStaticMarkup(<QueryClientProvider client={client}><RouterProvider router={router} /></QueryClientProvider>);
  expect(html).toContain("История объекта № 42");
  expect(html).toContain("Совпадений не найдено.");
  expect(html).not.toContain("Начните с точного события");
  expect(html).not.toMatch(/<button[^>]+disabled[^>]*>Построить историю/);
  expect(html).toContain('href="/app/security-events-report?tab=chains">Назад к исходному отчёту</a>');
});

it("investigation history carries its exact selection and bounds to the chosen proof", async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  const search = "event_db_id=517548&entity_id=5632&q=%E2%80%94&scope=all&time_from=2026-09-10T12%3A00%3A00.123001Z&time_to=2026-09-10T12%3A00%3A00.123999Z&timezone=Asia%2FNovosibirsk";
  client.setQueryData([...investigationQueryKey(investigationContext(new URLSearchParams(search))), "pages"], { pageParams: [null], pages: [{
    state: "available", query: "—", scope: "all",
    timeline: [{ event_db_id: 517550, event_id: 4624, time_utc: "2026-09-10T12:00:01Z", title: "Вход", server: "DC1", actor: null, target: null, channel: "Security", severity: "info", classification_origin: "catalog_base", card_completeness: "not_applicable", catalogued: true }],
    findings: [{ id: "finding-1", severity: "high", title: "Подтверждённая находка" }], next_checks: [], limits: {}, anchor_event_db_id: 517548,
    summary: { events_returned: 1, has_more: false, attention_level: "unknown", story: "", why_it_matters: "" },
  }] });
  client.setQueryData(["investigation-cases"], { items: [] });
  client.setQueryData(["bootstrap"], {});
  client.setQueryData(["event-relations", 517550], { items: [{ relation_type: "explicit_event_link", relation_origin: "stored", related_event_db_id: 517551, confidence: 1, reason: "Сохранённая связь." }] });
  const root = createRootRoute();
  const investigations = createRoute({ getParentRoute: () => root, path: "/investigations", component: InvestigationWorkspacePage });
  const events = createRoute({ getParentRoute: () => root, path: "/events/$eventId", component: () => null });
  const router = createRouter({ routeTree: root.addChildren([investigations, events]), basepath: "/app",
    history: createMemoryHistory({ initialEntries: [`/app/investigations?${search}`] }) });
  await router.load();
  const html = renderToStaticMarkup(<QueryClientProvider client={client}><RouterProvider router={router} /></QueryClientProvider>);
  const href = html.match(/href="([^"]+)"[^>]*>Открыть точную карточку</)?.[1];
  expect(href).toBeDefined();
  const url = new URL(href!.replaceAll("&amp;", "&"), "http://localhost");
  expect(url.pathname).toBe("/app/events/517550");
  expect(Object.fromEntries(url.searchParams)).toEqual({ event_db_id: "517550", entity_id: "5632", q: "—", scope: "all", time_from: "2026-09-10T12:00:00.123001Z", time_to: "2026-09-10T12:00:00.123999Z", timezone: "Asia/Novosibirsk" });
  const relationHref = html.match(/href="([^"]+)"[^>]*>Открыть событие DB 517551</)?.[1];
  expect(relationHref).toBeDefined();
  const relationUrl = new URL(relationHref!.replaceAll("&amp;", "&"), "http://localhost");
  expect(relationUrl.pathname).toBe("/app/events/517551");
  expect(Object.fromEntries(relationUrl.searchParams)).toEqual({ event_db_id: "517551", entity_id: "5632", q: "—", scope: "all", time_from: "2026-09-10T12:00:00.123001Z", time_to: "2026-09-10T12:00:00.123999Z", timezone: "Asia/Novosibirsk" });
  expect(html).toContain("Класс каталога: информационный");
  expect(html).not.toContain("Риск ИБ: info");
  expect(html).toContain("Риск ИБ: high");
});
