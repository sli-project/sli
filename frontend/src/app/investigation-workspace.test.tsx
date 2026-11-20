// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, ApiResponseError } from "../api/client";

const state = vi.hoisted(() => ({ workspace: vi.fn(), cases: vi.fn(), relations: vi.fn(), bootstrap: vi.fn() }));

vi.mock("./App", async (importOriginal) => ({ ...(await importOriginal<typeof import("./App")>()), useTimeZone: () => ({ timeZone: "UTC" }) }));
vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return { ...actual, api: { ...actual.api,
    investigationWorkspace: (params: URLSearchParams) => state.workspace(params),
    investigationCases: () => state.cases(),
    eventRelations: (id: number) => state.relations(id),
    bootstrap: () => state.bootstrap(),
  } };
});

import { localeRuntime, setLocale, t } from "../i18n";
import { InvestigationWorkspacePage } from "./investigation-workspace";

async function mount(search: string, client = new QueryClient({ defaultOptions: { queries: { retry: false } } })) {
  const root = createRootRoute();
  const investigations = createRoute({ getParentRoute: () => root, path: "/investigations", component: InvestigationWorkspacePage });
  const events = createRoute({ getParentRoute: () => root, path: "/events/$eventId", component: () => null });
  const detail = createRoute({ getParentRoute: () => root, path: "/investigations/$investigationId", component: () => null });
  const router = createRouter({ routeTree: root.addChildren([investigations, events, detail]), basepath: "/app", history: createMemoryHistory({ initialEntries: [`/app/investigations?${search}`] }) });
  await router.load();
  return render(<QueryClientProvider client={client}><RouterProvider router={router}/></QueryClientProvider>);
}

beforeEach(() => { vi.stubGlobal("scrollTo", vi.fn()); });
afterEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("ru"); vi.restoreAllMocks(); cleanup(); vi.unstubAllGlobals(); vi.clearAllMocks(); });

const workspaceOf = (overrides: Record<string, unknown> = {}) => ({
  api_version: "v1", state: "ok", query: "", scope: "all", anchor_event_db_id: 517548, findings: [], next_checks: ["Проверить источник"], limits: {},
  timeline: [
    { event_db_id: 517548, event_id: 4624, time_utc: "2026-09-10T22:35:00Z", title: "Вход", server: "DC1", actor: "alice", target: null, channel: "Security", severity: "info", classification_origin: "catalog_base", catalogued: true },
    { event_db_id: 517549, event_id: 4625, time_utc: "2026-09-10T22:30:00Z", title: "Неудачный вход", server: "DC1", actor: null, target: null, channel: "Security", severity: "medium", catalogued: false },
  ],
  summary: { events_returned: 2, has_more: false, attention_level: "unknown", story: "Была история", why_it_matters: "" },
  ...overrides,
});

it.each(["ru", "en"] as const)("uses case status envelopes in the %s workspace without changing titles", async (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  state.bootstrap.mockResolvedValue({});
  state.cases.mockResolvedValue({ items: [{ id: 7, title: "Synthetic case", status: "confirmed",
    status_message: { code: "investigations.caseStatus.confirmed", params: {}, text: "other language" } }] });
  state.workspace.mockResolvedValue(workspaceOf());
  state.relations.mockResolvedValue({ items: [] });
  try {
    await mount("event_db_id=517548&scope=all&timezone=UTC");
    expect(await screen.findByText("Synthetic case")).toBeTruthy();
    expect(screen.getByText(locale === "en" ? "Confirmed" : "Подтверждено")).toBeTruthy();
    expect(screen.queryByText("other language")).toBeNull();
  } finally { setLocale("ru"); vi.restoreAllMocks(); }
});

it("requires a reason before changing the finding from the investigation workspace", async () => {
  const update = vi.spyOn(api, "updateFinding");
  state.bootstrap.mockResolvedValue({ effective_role: "operator" });
  state.cases.mockResolvedValue({ items: [] });
  state.relations.mockResolvedValue({ items: [] });
  state.workspace.mockResolvedValue(workspaceOf({ findings: [{ id: 1, title: "Test finding", status: "new" }] }));
  await mount("event_db_id=1&scope=all&timezone=UTC");
  const save = await screen.findByRole("button", { name: t("investigations.result.caseSave") }) as HTMLButtonElement;
  expect(save.disabled).toBe(true);
  expect((screen.getByLabelText(t("investigations.result.caseNoteLabel")) as HTMLInputElement).required).toBe(true);
  fireEvent.submit(save.closest("form")!);
  expect(update).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText(t("investigations.result.caseNoteLabel")), { target: { value: "Test review reason" } });
  expect(save.disabled).toBe(false);
  update.mockRestore();
});

it("continues bounded history while retaining the anchor and presentation context", async () => {
  state.bootstrap.mockResolvedValue({});
  state.cases.mockResolvedValue({ items: [] });
  state.relations.mockResolvedValue({ items: [] });
  state.workspace.mockImplementation((params: URLSearchParams) => Promise.resolve(params.has("cursor")
    ? workspaceOf({ timeline: [{ event_db_id: 517550, event_id: 4624, title: "Synthetic next evidence", catalogued: false }], next_cursor: null })
    : workspaceOf({ next_cursor: "history-next", summary: { events_returned: 2, has_more: true, attention_level: "unknown", story: "", why_it_matters: "" } })));
  await mount("event_db_id=517548&scope=all&timezone=UTC");
  await userEvent.click(await screen.findByRole("button", { name: "Показать дальше" }));
  expect(await screen.findByText("Synthetic next evidence", { selector: "strong" })).toBeTruthy();
  expect(screen.getByText("Вход", { selector: "strong" })).toBeTruthy();
  expect(Object.fromEntries(state.workspace.mock.calls[1][0])).toMatchObject({ event_db_id: "517548", scope: "all", timezone: "UTC", cursor: "history-next" });
  expect(screen.queryByRole("button", { name: "Показать дальше" })).toBeNull();
});

it("retains read history after a continuation failure and retries the same cursor", async () => {
  state.bootstrap.mockResolvedValue({});
  state.cases.mockResolvedValue({ items: [] });
  state.relations.mockResolvedValue({ items: [] });
  state.workspace.mockImplementation((params: URLSearchParams) => params.has("cursor")
    ? Promise.reject(new ApiResponseError(503))
    : Promise.resolve(workspaceOf({ next_cursor: "history-next" })));
  await mount("event_db_id=517548&scope=all&timezone=UTC");
  await userEvent.click(await screen.findByRole("button", { name: "Показать дальше" }));
  expect(await screen.findByText("Продолжение не загружено. Повторите попытку.")).toBeTruthy();
  expect(screen.getByText("Вход", { selector: "strong" })).toBeTruthy();
  state.workspace.mockResolvedValue(workspaceOf({ timeline: [] }));
  await userEvent.click(screen.getByRole("button", { name: "Показать дальше" }));
  expect(String(state.workspace.mock.lastCall![0])).toContain("cursor=history-next");
  expect(screen.getByText("Вход", { selector: "strong" })).toBeTruthy();
});

it.each([
  ["critical", "danger"], ["high", "danger"], ["unknown", "neutral"],
  ["future_high", "neutral"], ["low", "success"], ["normal", "success"],
])("renders attention level %s with the explicit %s tone", async (attention, tone) => {
  state.bootstrap.mockResolvedValue({});
  state.cases.mockResolvedValue({ items: [] });
  state.relations.mockResolvedValue({ items: [] });
  state.workspace.mockResolvedValue(workspaceOf({ summary: { events_returned: 2, has_more: false, attention_level: attention, story: "", why_it_matters: "" } }));
  await mount("event_db_id=517548&timezone=UTC");
  const label = await screen.findByText("Уровень внимания", { selector: ".sli-ds-metric__label" });
  expect(label.closest(".sli-ds-metric")?.getAttribute("data-tone")).toBe(tone);
});

it("a broken context shows an error and makes no request", async () => {
  await mount("event_db_id=517548&timezone=Unknown%2FZone");
  const alert = await screen.findByRole("alert");
  expect(alert.textContent).toContain("Контекст расследования не принят");
  expect(alert.textContent).toContain("invalid_timezone");
  expect(state.workspace).not.toHaveBeenCalled();
  expect(state.cases).not.toHaveBeenCalled();
});

it("a duplicated return_to is rejected before any request", async () => {
  await mount("event_db_id=517548&return_to=%2Fapp%2Fa&return_to=%2Fapp%2Fb");
  expect((await screen.findByRole("alert")).textContent).toContain("invalid_return_to");
  expect(state.workspace).not.toHaveBeenCalled();
});

it("renders the timeline in the URL time zone with exact evidence links that keep the context", async () => {
  state.bootstrap.mockResolvedValue({});
  state.cases.mockResolvedValue({ items: [{ id: 7, title: "Дело о входе", owner: null, status: "open", updated_at: "2026-09-10T10:00:00Z" }], limit: 50 });
  state.workspace.mockResolvedValue(workspaceOf());
  state.relations.mockResolvedValue({ items: [{ relation_type: "explicit_event_link", relation_origin: "stored", related_event_db_id: 517551, confidence: 1, reason: "Сохранённая связь." }] });
  await mount("event_db_id=517548&scope=all&timezone=UTC&return_to=%2Fapp%2Fsecurity-events-report%3Ftab%3Dchains");
  const exact = await screen.findByRole("link", { name: "Открыть точную карточку" });
  const url = new URL(exact.getAttribute("href")!, "http://localhost");
  expect(url.pathname).toBe("/app/events/517548");
  expect(Object.fromEntries(url.searchParams)).toMatchObject({ event_db_id: "517548", scope: "all", timezone: "UTC" });
  const relation = await screen.findByRole("link", { name: "Открыть событие DB 517551" });
  expect(new URL(relation.getAttribute("href")!, "http://localhost").pathname).toBe("/app/events/517551");
  expect(screen.getAllByText("Неудачный вход").length).toBeGreaterThan(0);
  expect(screen.getAllByText(/22:35:00/).length).toBeGreaterThan(0);
  expect(screen.getByRole("link", { name: "Назад к исходному отчёту" }).getAttribute("href")).toBe("/app/security-events-report?tab=chains");
  expect(screen.getByRole("link", { name: "INV-0000007" }).getAttribute("href")).toContain("/app/investigations/7");
  expect(String(state.workspace.mock.calls[0][0])).toContain("event_db_id=517548");
});

it("shows a failed history as unavailable, not as an empty result", async () => {
  state.bootstrap.mockResolvedValue({});
  state.cases.mockResolvedValue({ items: [], limit: 50 });
  state.workspace.mockRejectedValue(new ApiResponseError(500));
  await mount("q=evidence-reader&scope=important");
  const message = await screen.findByText(/Это отказ построения истории/);
  expect(message.closest("[data-state]")?.getAttribute("data-state")).toBe("unavailable");
  expect(screen.queryByText(/Совпадений не найдено/)).toBeNull();
});

it("shows an empty result honestly and a denied history as denied", async () => {
  state.bootstrap.mockResolvedValue({});
  state.cases.mockResolvedValue({ items: [], limit: 50 });
  state.workspace.mockResolvedValue(workspaceOf({ state: "empty", timeline: [], summary: { events_returned: 0, has_more: false, attention_level: "unknown", story: "", why_it_matters: "" } }));
  await mount("q=nobody");
  expect(await screen.findByText(/Это не доказывает отсутствие активности/)).toBeTruthy();
  cleanup();
  state.workspace.mockRejectedValue(new ApiResponseError(403));
  await mount("q=forbidden");
  const denied = await screen.findByText(/Это отказ построения истории/);
  expect(denied.closest("[data-state]")?.getAttribute("data-state")).toBe("denied");
});

it("renders English coded correlations while retaining case titles and unknown reasons", async () => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("en");
  try {
    state.bootstrap.mockResolvedValue({});
    state.cases.mockResolvedValue({ items: [{ id: 7, title: "Название дела из источника", status: "active", updated_at: "2026-10-01T00:00:00Z" }], limit: 50 });
    state.workspace.mockResolvedValue(workspaceOf());
    state.relations.mockResolvedValue({ confidence_contract: { rule_policy_score: "Серверный текст" }, items: [{
      relation_type: "computed_correlation", relation_origin: "computed", confidence_kind: "rule_policy_score",
      related_event_db_id: 2, confidence: 0.8, reason: "Серверная причина",
      reason_code: "same_task_same_server_time_window", reason_params: { time_delta_seconds: 12 },
    }, {
      relation_type: "computed_correlation", related_event_db_id: 3, confidence: 0.8,
      reason_code: "future-rule", reason: "Неизвестная причина из источника",
    }] });
    await mount("event_db_id=517548&scope=all&timezone=UTC");
    expect(await screen.findByText("Matching task name and server; time difference 12 s.")).toBeTruthy();
    expect(screen.getByText("Correlation rule strength score; neither a probability nor proof of causation.")).toBeTruthy();
    expect(screen.getByText("Неизвестная причина из источника")).toBeTruthy();
    expect(screen.getByText("Название дела из источника")).toBeTruthy();
    expect(screen.queryByText("Серверная причина")).toBeNull();
  } finally { setLocale("ru"); vi.restoreAllMocks(); }
});

it("renders coded timeline titles, story and checks in English without translating case names", async () => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("en");
  state.bootstrap.mockResolvedValue({});
  state.cases.mockResolvedValue({ items: [{ id: 7, title: "Синтетическое дело", status: "open" }] });
  state.relations.mockResolvedValue({ items: [] });
  const code = "Security:Microsoft-Windows-Security-Auditing:4719";
  state.workspace.mockResolvedValue(workspaceOf({
    timeline: [{ event_db_id: 517548, event_id: 4719, title: "Изменена политика аудита", title_code: `${code}.title`, catalogued: true }],
    summary: { events_returned: 1, attention_level: "unknown", story: "Серверное описание", story_code: `${code}.summary`, why_it_matters: "Серверное пояснение", why_it_matters_code: "investigations.exact_chain" },
    next_checks: ["Серверный совет"], next_check_codes: [`${code}.checks.0`],
  }));
  try {
    await mount("event_db_id=517548&scope=all&timezone=UTC");
    expect((await screen.findAllByText("Audit policy changed")).length).toBeGreaterThan(0);
    expect(screen.getByText("Changing the audit policy reduces confidence in log completeness.")).toBeTruthy();
    expect(screen.getByText("The sequence starts with the selected exact evidence and contains only explainable links.")).toBeTruthy();
    expect(screen.getByText("Check who changed the audit policy and why, and compare the result with the approved policy.")).toBeTruthy();
    expect(screen.getByText("Синтетическое дело")).toBeTruthy();
    expect(screen.queryByText("Серверный совет")).toBeNull();
  } finally { setLocale("ru"); vi.restoreAllMocks(); }
});

it.each([[503, "ru"], [401, "ru"], [403, "ru"], [503, "en"], [401, "en"], [403, "en"]] as const)("reports cached workspace refresh failure %s without leaking denied data", async (status, locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  state.bootstrap.mockResolvedValue({}); state.cases.mockResolvedValue({ items: [] });
  state.relations.mockResolvedValue({ items: [] }); state.workspace.mockResolvedValue(workspaceOf());
  await mount("event_db_id=517548&scope=all&timezone=UTC", client);
  await screen.findByText("Вход", { selector: "strong" });
  state.workspace.mockRejectedValue(new ApiResponseError(status));
  await act(() => client.invalidateQueries({ queryKey: ["investigation"] }));
  await waitFor(() => expect(document.querySelector(`[data-state="${status === 503 ? "stale" : "denied"}"]`)).not.toBeNull());
  expect(Boolean(screen.queryByText("Вход", { selector: "strong" }))).toBe(status === 503);
  if (status !== 503) {
    state.workspace.mockRejectedValue(new ApiResponseError(503));
    await act(() => client.invalidateQueries({ queryKey: ["investigation"] }));
    await waitFor(() => expect(document.querySelector('[data-state="unavailable"]')).not.toBeNull());
    expect(screen.queryByText("Вход", { selector: "strong" })).toBeNull();
    expect(client.getQueryCache().find({ queryKey: ["investigation"], exact: false })?.state.data).toBeUndefined();
    cleanup();
    await mount("event_db_id=999&scope=all&timezone=UTC", client);
    cleanup();
    await mount("event_db_id=517548&scope=all&timezone=UTC", client);
    await waitFor(() => expect(document.querySelector('[data-state="unavailable"]')).not.toBeNull());
    expect(screen.queryByText("Вход", { selector: "strong" })).toBeNull();
    state.workspace.mockResolvedValue(workspaceOf());
    await act(() => client.invalidateQueries({ queryKey: ["investigation"] }));
    expect(await screen.findByText("Вход", { selector: "strong" })).toBeTruthy();
  }
  if (status === 503) {
    state.workspace.mockResolvedValue(workspaceOf());
    await userEvent.click(screen.getByRole("button", { name: t("state.retry") }));
    await waitFor(() => expect(document.querySelector('[data-state="stale"]')).toBeNull());
  }
});

it("conceals cached history and continuation controls when next-page access is revoked", async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  state.bootstrap.mockResolvedValue({}); state.cases.mockResolvedValue({ items: [] }); state.relations.mockResolvedValue({ items: [] });
  state.workspace.mockImplementation((params: URLSearchParams) => params.has("cursor")
    ? Promise.reject(new ApiResponseError(403))
    : Promise.resolve(workspaceOf({ next_cursor: "history-next" })));
  await mount("event_db_id=517548&scope=all&timezone=UTC", client);
  await userEvent.click(await screen.findByRole("button", { name: t("investigations.workspace.showMore") }));
  await waitFor(() => expect(document.querySelector('[data-state="denied"]')).not.toBeNull());
  expect(screen.queryByText("Вход", { selector: "strong" })).toBeNull();
  expect(screen.queryByRole("button", { name: t("investigations.workspace.showMore") })).toBeNull();
  state.workspace.mockRejectedValue(new ApiResponseError(503));
  await act(() => client.invalidateQueries({ queryKey: ["investigation"] }));
  await waitFor(() => expect(document.querySelector('[data-state="unavailable"]')).not.toBeNull());
  expect(screen.queryByText("Вход", { selector: "strong" })).toBeNull();
  expect(document.querySelector('[data-state="stale"]')).toBeNull();
});
