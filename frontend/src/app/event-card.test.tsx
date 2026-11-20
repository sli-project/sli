// @vitest-environment jsdom
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { expect, it, vi } from "vitest";

const captured = vi.hoisted(() => ({ options: [] as Array<{ mutationFn: (variables: never) => Promise<unknown> }> }));

vi.mock("@tanstack/react-query", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@tanstack/react-query")>();
  return {
    ...actual,
    useMutation: (options: { mutationFn: (variables: never) => Promise<unknown> }) => {
      captured.options.push(options);
      return { data: undefined, variables: undefined, isPending: false, isError: false, isSuccess: false, mutate: vi.fn() };
    },
  };
});

import { localeRuntime, setLocale } from "../i18n";
import { api, type EventDetail } from "../api/client";
import { EventCardPage, RawSections } from "./event-card";

const EVENT_PATH = "/app/events/517548?time_from=2026-09-10T00%3A00%3A00Z&time_to=2026-09-11T00%3A00%3A00Z&timezone=UTC";

async function render(options: { role?: string; relations?: unknown; entities?: unknown; semantics?: Record<string, unknown>; expired?: boolean } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["bootstrap"], { effective_role: options.role ?? "viewer" });
  client.setQueryData(["event", "517548"], { item: {
    event_db_id: 517548, event_id: 4722, time_created_utc: "2026-09-10T12:00:00Z", subject: "admin", target: "S-1-5-21-affected",
    server: "dc01.example.test", source: null, provider_name: null, event_record_id: null, event_data: { TargetUserName: "analyst" }, message_text: null,
    semantics: options.semantics ?? { title: "Изменение учётной записи", final_risk: "low", risk: "Низкий", assessment_confidence: "unknown", summary: "Наблюдение.", facts: [["Что изменилось", "Пароль"]], checks: [], known: true, classification_origin: "catalog_base", card_completeness: "not_applicable" },
    source_payload_state: options.expired ? "expired" : undefined,
  } });
  if (options.relations !== null) client.setQueryData(["event-relations", "517548"], options.relations ?? { items: [] });
  client.setQueryData(["event-entities", "517548"], options.entities ?? { items: [] });
  client.setQueryData(["investigation-cases"], { items: [{ id: 72, title: "Existing" }] });
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
    expect(html).toContain(locale === "ru" ? "Наблюдение за учёткой" : "Account watch");
    expect(html).toContain(locale === "ru" ? "Уверенность не изменена" : "Confidence is unchanged");
    expect(await render()).not.toContain(locale === "ru" ? "Наблюдение за учёткой" : "Account watch");
  } finally {
    setLocale("ru"); vi.restoreAllMocks();
  }
});

it("keeps historical facts and relations available when source text expires", async () => {
  const html = await render({ expired: true, relations: { items: [{
    relation_type: "computed_correlation", related_event_db_id: 2, confidence: 0.8,
  }] } });
  expect(html).toContain("Исходный текст удалён по сроку хранения");
  expect(html).toContain("Пароль");
  expect(html).toContain("Показано до 1 связей");
  expect(html).not.toContain('data-state="unavailable"');
});

it.each(["ru", "en"] as const)("explains expired raw sections and displays retained facts in %s", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  try {
    const html = renderToStaticMarkup(<RawSections timeZone="UTC" item={{
      event_db_id: 41, event_id: 4624, source_payload_state: "expired",
      retained_facts: { logon_type: 3 }, event_data: {}, message_text: "",
    } as EventDetail}/>);
    expect(html).toContain(locale === "ru" ? "Исходный текст удалён по сроку хранения" : "source text was deleted");
    expect(html).toContain(locale === "ru" ? "Сохранённые факты" : "Retained facts");
    expect(html).toContain("logon_type");
    expect(html).not.toContain('data-state="unavailable"');
    expect(html).not.toContain('data-state="empty"');
  } finally {
    setLocale("ru"); vi.restoreAllMocks();
  }
});

it("explains that an expired sign-in event is represented by a session", () => {
  const html = renderToStaticMarkup(<RawSections timeZone="UTC" item={{
    event_db_id: 41, event_id: 4624, source_payload_state: "expired",
    read_representation: "authentication_session", source_event_state: "expired_represented_by_session",
    retained_facts: { state: "incomplete", quality_reason: "incomplete_missing_close" },
  } as EventDetail}/>);
  expect(html).toContain("Показана сохранённая сессия входа");
  expect(html).toContain("полнота сбора не доказана");
  expect(html).not.toContain('data-state="unavailable"');
  expect(html).not.toContain('data-state="error"');
});

it("does not present relations that were not received as an empty result", async () => {
  const pending = await render({ relations: null });
  expect(pending).not.toContain("не найдены");
  const empty = await render({ relations: { items: [] } });
  expect(empty).toContain('data-state="empty"');
  expect(empty).toContain("не найдены");
  expect(pending).toContain("Показано до — связей");
  expect(empty).toContain("Показано до 0 связей");
});

it.each([true, false, undefined])("shows bounded relation counts and only warns on server truncation (%s)", async (truncated) => {
  const html = await render({ relations: { truncated, items: [{
    relation_type: "computed_correlation", related_event_db_id: 2, confidence: 0.8,
  }] } });
  expect(html).toContain("Показано до 1 связей");
  if (truncated) {
    expect(html).toContain("Выборка связей усечена. Есть дополнительные связи.");
    const link = html.match(/<a[^>]*>Уточнить период в контексте расследования<\/a>/)?.[0];
    expect(link).toContain("/app/investigations?");
    expect(link).toContain("event_db_id=517548");
    expect(link).toContain("time_from=");
    expect(link).toContain("timezone=UTC");
  } else {
    expect(html).not.toContain("Выборка связей усечена");
    expect(html).not.toContain("Уточнить период в контексте расследования");
  }
});

it("shows an entity query timeout as unavailable with an unknown count", async () => {
  const html = await render({ entities: { api_version: "v1", event_db_id: 517548, event_found: null, evidence_status: "timeout", items: [], limit: 100 } });
  const section = html.match(/<section id="evidence"[\s\S]*?<\/section>/)?.[0];
  expect(section).toBeDefined();
  expect(section).toContain('data-state="unavailable"');
  expect(section).toContain("превышено время запроса");
  expect(section).toContain("Это не означает, что связей нет.");
  expect(section).toContain('class="sli-ds-chip">—</span>');
  expect(section).not.toContain('data-state="empty"');
  expect(section).not.toContain('class="sli-ds-chip">0</span>');
});

it("add-to-case and create-case call the api with the exact event id", async () => {
  captured.options.length = 0;
  await render({ role: "operator" });
  const create = vi.spyOn(api, "createInvestigation").mockResolvedValue({ id: 71 } as never);
  const add = vi.spyOn(api, "addInvestigationEvent").mockResolvedValue({} as never);
  const [createOptions, addOptions] = captured.options.slice(0, 2);
  await createOptions.mutationFn({ title: "Дело", owner: " ", eventDbId: 517548 } as never);
  await addOptions.mutationFn({ caseId: 72, eventDbId: 517548 } as never);
  expect(create).toHaveBeenCalledWith({ title: "Дело", owner: null, event_db_id: 517548 });
  expect(add).toHaveBeenCalledWith(72, { event_db_id: 517548 });
});

it("does not offer case mutations to a role without the permission", async () => {
  const html = await render({ role: "guest" });
  expect(html).not.toContain("Создать дело и добавить evidence");
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
    expect(html).toContain("Enabling an account may restore access");
    expect(html).toContain("Matching LogonId and server; time difference 3 s.");
    expect(html).toContain("neither a probability nor proof of causation");
    expect(html).toContain("Showing up to 1 relations");
    expect(html).toContain("The relations result is truncated. Additional relations exist.");
    expect(html).toContain("Refine the time range in the investigation context");
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
