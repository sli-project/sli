// @vitest-environment jsdom
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { expect, it, vi } from "vitest";

import { localeRuntime, setLocale, t } from "../i18n";
import { api, type EventDetail } from "../api/client";
import { EventCardPage, RawSections } from "./event-card";

const EVENT_PATH = "/app/events/517548?time_from=2026-09-10T00%3A00%3A00Z&time_to=2026-09-11T00%3A00%3A00Z&timezone=UTC";

async function render(options: { role?: string; relations?: unknown; entities?: unknown; semantics?: Record<string, unknown>; sourceState?: EventDetail["source_payload_state"] } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["bootstrap"], { effective_role: options.role ?? "viewer" });
  client.setQueryData(["event", "517548"], { item: {
    event_db_id: 517548, event_id: 4722, time_created_utc: "2026-09-10T12:00:00Z", subject: "admin", target: "S-1-5-21-affected",
    server: "dc01.example.test", source: null, provider_name: null, event_record_id: null, event_data: { TargetUserName: "analyst" }, message_text: null,
    semantics: options.semantics ?? { title: "Изменение учётной записи", final_risk: "low", risk: "Низкий", assessment_confidence: "unknown", summary: "Наблюдение.", facts: [["Что изменилось", "Пароль"]], checks: [], known: true, classification_origin: "catalog_base", card_completeness: "not_applicable" },
    source_payload_state: options.sourceState,
  } });
  if (options.relations !== null) client.setQueryData(["event-relations", "517548"], options.relations ?? { items: [] });
  client.setQueryData(["event-entities", "517548"], options.entities ?? { items: [] });
  client.setQueryData(["semantic-event-actions", "event_db_id=517548&time_from=2026-09-10T00%3A00%3A00Z&time_to=2026-09-11T00%3A00%3A00Z&timezone=UTC"], {
    state: "available", items: [{ canonical_action_id: "synthetic-action", status: "observed" }], limits: { synthetic_limit: 50 },
  });
  client.setQueryData(["semantic-event-scenarios", "event_db_id=517548&time_from=2026-09-10T00%3A00%3A00Z&time_to=2026-09-11T00%3A00%3A00Z&timezone=UTC"], { state: "empty", items: [] });
  const root = createRootRoute();
  const route = createRoute({ getParentRoute: () => root, path: "/events/$eventId", component: EventCardPage });
  const investigations = createRoute({ getParentRoute: () => root, path: "/investigations", component: () => null });
  const router = createRouter({ isServer: true, routeTree: root.addChildren([route, investigations]), basepath: "/app", history: createMemoryHistory({ initialEntries: [EVENT_PATH] }) });
  const search = EVENT_PATH.slice(EVENT_PATH.indexOf("?"));
  const globalScope = globalThis as unknown as { window?: { location: { href: string; search: string; pathname: string } } };
  const hadWindow = Object.hasOwn(globalScope, "window");
  const previousWindow = globalScope.window;
  globalScope.window = { location: { href: `http://localhost${EVENT_PATH}`, search, pathname: "/app/events/517548" } };
  try {
    await router.load();
    return renderToStaticMarkup(<QueryClientProvider client={client}><RouterProvider router={router}/></QueryClientProvider>);
  } finally {
    if (hadWindow) globalScope.window = previousWindow;
    else Reflect.deleteProperty(globalScope, "window");
  }
}

it("renders the exact event facts from the api response", async () => {
  const html = await render();
  expect(html).toContain("Изменение учётной записи");
  expect(html).toContain("Что изменилось");
  expect(html).toContain("Пароль");
  expect(html).toContain("dc01.example.test");
  expect(html).toContain("12:00:00");
});

it.each(["ru", "en"] as const)("shows server-calculated watch priority in %s", async (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  try {
    const html = await render({ semantics: {
      title: "Synthetic activity", final_risk: "low", risk: "low", assessment_confidence: "low",
      facts: [], checks: [], known: true, summary: "Synthetic observation",
      watch_priority: { base_severity: "info", effective_severity: "low", reason: "watch" },
    } });
    expect(html).toContain(locale === "ru" ? "Приоритет наблюдаемой учётной записи" : "Watched account priority");
    expect(html).not.toContain(locale === "ru" ? "Уверенность не изменена" : "Confidence is unchanged");
    expect(await render()).not.toContain(locale === "ru" ? "Приоритет наблюдаемой учётной записи" : "Watched account priority");
  } finally {
    setLocale("ru"); vi.restoreAllMocks();
  }
});

it.each(["expired", "archive_unavailable"] as const)("shows one dated source-record message for %s and keeps facts and links", async (sourceState) => {
  const html = await render({ sourceState, relations: { items: [{
    relation_type: "computed_correlation", related_event_id: 4624, related_event_db_id: 2, confidence: 0.8,
  }] } });
  const message = t(sourceState === "expired" ? "events.card.recordExpired" : "events.card.recordUnavailable", {
    id: 4722, time: "10.09.2026, 12:00:00",
  });
  expect(html.split(message)).toHaveLength(2);
  expect(html).toContain("Пароль");
  expect(html).toMatch(/href="\/app\/events\/2\?[^"]*">Event 4624 · DB 2/);
  expect(html).not.toContain("sli-ds-state--banner");
  expect(html).not.toContain("DB 517548; источник");
});

it.each(["ru", "en"] as const)("uses dashes for absent source fields and shows retained facts in %s", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  try {
    const html = renderToStaticMarkup(<RawSections timeZone="UTC" item={{
      event_db_id: 41, event_id: 4624, source_payload_state: "expired",
      read_representation: "authentication_session", source_event_state: "expired_represented_by_session",
      retained_facts: { logon_type: 3 }, event_data: {}, message_text: "",
    } as EventDetail}/>);
    expect(html).toContain(locale === "ru" ? "Сохранённые факты" : "Retained facts");
    expect(html).toContain("logon_type");
    expect(html).toContain(">—<");
    expect(html).not.toContain("sli-ds-state");
    expect(html).not.toContain(locale === "ru" ? "Показана сохранённая сессия входа" : "A retained sign-in session is shown");
  } finally {
    setLocale("ru"); vi.restoreAllMocks();
  }
});

it("does not present relations that were not received as an empty result", async () => {
  const empty = t("events.card.relationsEmpty");
  expect(await render({ relations: null })).not.toContain(empty);
  expect(await render({ relations: { items: [] } })).toContain(empty);
});

it("keeps actual relation and action rows without service limits, summaries or truncation notices", async () => {
  const html = await render({ relations: { truncated: true, items: [{
    relation_type: "computed_correlation", related_event_db_id: 2, related_event_id: 4624, confidence: 0.8,
    relation_rule: "synthetic_rule", evidence_fields: ["synthetic_field"],
  }] } });
  expect(html).toContain("Event 4624 · DB 2");
  expect(html).toContain(t("events.card.statusObserved"));
  expect(html).not.toContain("<details");
  expect(html).not.toMatch(/связей усечена|Показано до|Наблюдение\.|synthetic_rule|synthetic_field|synthetic_limit|synthetic-action/);
});

it("shows an entity query timeout without an empty-result message or a status banner", async () => {
  const html = await render({ entities: { api_version: "v1", event_db_id: 517548, event_found: null, evidence_status: "timeout", items: [], limit: 100 } });
  const section = html.match(/<section id="evidence"[\s\S]*?<\/section>/)?.[0];
  expect(section).toBeDefined();
  expect(section).toContain(t("events.card.entitiesTimeout"));
  expect(section).not.toContain(t("events.card.entitiesEmpty"));
  expect(section).not.toContain("sli-ds-state");
});

it.each(["guest", "admin"])("keeps case actions out of the event card for a %s", async (role) => {
  const list = vi.spyOn(api, "investigationCases");
  try {
    const html = await render({ role });
    expect(html).not.toMatch(/Создать дело|Добавить в существующее дело|case-title|existing-case/);
    expect(list).not.toHaveBeenCalled();
  } finally {
    list.mockRestore();
  }
});

it("renders English semantic descriptions and relation reasons without changing object facts", async () => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  try {
    setLocale("en");
    const html = await render({ semantics: {
      title: "Серверный заголовок", summary: "Серверное пояснение",
      title_code: "Security:Microsoft-Windows-Security-Auditing:4722.title",
      summary_code: "Security:Microsoft-Windows-Security-Auditing:4722.summary",
      facts: [["Fixture object", "Описание объекта из источника"]], checks: [], known: true,
    }, relations: { truncated: true, confidence_contract: { rule_policy_score: "Серверное объяснение силы" }, items: [{
      relation_type: "computed_correlation", relation_origin: "computed", confidence_kind: "rule_policy_score",
      related_event_db_id: 2, confidence: 0.95, reason: "Серверная причина",
      reason_code: "same_logon_id_same_server", reason_params: { time_delta_seconds: 3 },
    }] } });
    expect(html).toContain("Account enabled");
    expect(html).not.toContain("Enabling an account may restore access");
    expect(html).toContain("Matching LogonId and server; time difference 3 s.");
    expect(html).not.toContain("neither a probability nor proof of causation");
    expect(html).not.toContain("The relations result is truncated.");
    expect(html).toContain("Описание объекта из источника");
    expect(html).not.toContain("Серверный заголовок");
    expect(html).not.toContain("Серверная причина");
  } finally {
    setLocale("ru"); vi.restoreAllMocks(); vi.unstubAllGlobals();
  }
});

it("renders audit event facts and catalog checks in English", async () => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("en");
  try {
    const html = await render({ semantics: {
      title: "Изменена политика аудита", title_code: "Security:Microsoft-Windows-Security-Auditing:4719.title",
      summary: "Изменение политики аудита снижает доверие к полноте логов.", summary_code: "Security:Microsoft-Windows-Security-Auditing:4719.summary",
      facts: [["Событие", "Изменена политика аудита"], ["Сервер", "fixture"]], fact_label_codes: ["facts.event", "facts.server"],
      checks: ["Проверить, кто и зачем изменил аудит, и сверить результат с согласованной политикой."], check_codes: ["Security:Microsoft-Windows-Security-Auditing:4719.checks.0"], known: true,
    } });
    expect(html).toContain("Audit policy changed");
    expect(html).toContain("Server");
    expect(html).toContain("Check who changed the audit policy and why");
    expect(html).not.toContain("Изменена политика аудита");
    expect(html).not.toContain("Проверить, кто");
  } finally { setLocale("ru"); vi.restoreAllMocks(); }
});
