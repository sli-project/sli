// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ApiResponseError } from "../api/client";

const state = vi.hoisted(() => ({ scenarios: vi.fn(), actions: vi.fn(), calibration: vi.fn(), review: vi.fn(), sigmaRules: vi.fn(), admission: vi.fn() }));

vi.mock("./App", async (importOriginal) => ({ ...(await importOriginal<typeof import("./App")>()), useTimeZone: () => ({ timeZone: "UTC" }) }));
vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return { ...actual, api: { ...actual.api,
    semanticScenarios: (params: URLSearchParams) => state.scenarios(params),
    semanticActions: (params: URLSearchParams) => state.actions(params),
    semanticCalibration: (hours: number) => state.calibration(hours),
    reviewSemanticScenario: (id: string, body: unknown) => state.review(id, body),
    sigmaRules: (scope: unknown) => state.sigmaRules(scope),
    updateSemanticControl: (change: unknown) => state.admission(change),
  } };
});

import { localeRuntime, setLocale, t } from "../i18n";
import { ScenariosPage } from "./scenarios";

const execution = (overrides: Record<string, unknown> = {}) => ({
  state: "active", schema_state: "ready", runtime_marker: 33, semantic_schema_marker: 29, feature_chain: {},
  worker: { state: "running", status: "running" }, finding_path_live: false, analyst_review_schema_ready: true, ...overrides,
});
const scenario = {
  scenario_id: "sc-1", scenario_kind: "lockout", result_class: "security_incident", status: "open", partition_key: "user:42", strict_keys: {},
  title: "Блокировка учётной записи", explanation: "Серия отказов.", first_seen_utc: "2026-09-10T10:00:00Z", last_seen_utc: "2026-09-10T11:00:00Z",
  risk_class: "high", raw_score: 70, display_score: 70, hard_critical: false, confidence: "medium", confidence_score: 50, confidence_factors: {},
  coverage_status: "partial", conclusion_state: "not_checked", completeness_snapshot: {}, step_count: 3, evidence_count: 2, contribution_count: 1,
  updated_at: "2026-09-10T11:00:00Z", review_count: 0, latest_review: null,
  evidence: [{ normalized_event_id: "abcdef1234567890", event_db_id: 517548, evidence_order: 1 }],
};
const workspace = (overrides: Record<string, unknown> = {}) => ({ api_version: "v1", state: "available", items: [scenario], has_more: false, filters: {}, limits: {}, execution: execution(), ...overrides });

async function mount(client = new QueryClient({ defaultOptions: { queries: { retry: false } } })) {
  const root = createRootRoute();
  const route = createRoute({ getParentRoute: () => root, path: "/scenarios", component: ScenariosPage });
  const events = createRoute({ getParentRoute: () => root, path: "/events/$eventId", component: () => null });
  const router = createRouter({ routeTree: root.addChildren([route, events]), basepath: "/app", history: createMemoryHistory({ initialEntries: ["/app/scenarios"] }) });
  await router.load();
  return render(<QueryClientProvider client={client}><RouterProvider router={router}/></QueryClientProvider>);
}

beforeEach(() => {
  state.sigmaRules.mockResolvedValue({ api_version: "v1", contract: "sli.sigma.rules.v1", read_only: true,
    state: "unavailable", reason: "source_unavailable_or_denied", metadata_state: "unavailable",
    sources: [], rules: [], scope: null, since: null, until: null, window_basis: "latest_retained_test_history" });
  vi.stubGlobal("scrollTo", vi.fn());
  if (!globalThis.crypto?.randomUUID) vi.stubGlobal("crypto", { randomUUID: () => "11111111-1111-4111-8111-111111111111" });
});
afterEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("ru"); vi.restoreAllMocks(); cleanup(); vi.clearAllMocks(); vi.unstubAllGlobals(); });

it.each(["ru", "en"] as const)("localizes calibration readiness facts, retaining unknown source states in %s", async (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  state.scenarios.mockResolvedValue(workspace({ state: "empty", items: [] }));
  state.calibration.mockResolvedValue({
    api_version: "v1", state: "available", window_hours: 24, execution: execution(), jobs: [], results: [], policies: [],
    calibration_readiness: {
      control_health: { total: 4 }, coverage: { total: 12 },
      source_coverage_integrity: { channels: { total: 3 }, state: "future-state", cursor_integrity: { actionable_rollbacks: 2, rejected_rollbacks: 5 }, gap_detection: { state: "future-gap" } },
      execution_reliability: { retries: 7, quarantined: 1 }, source_quality: { normalized: 15 },
      time_provenance: { future_clock_skew: 2, delayed_ingest: 3 },
      false_positive_rate: { rate_percent: null, decisive_labels: 3, minimum_decisive_sample: 10 },
    },
  });
  await mount();
  await userEvent.click(screen.getByRole("button", { name: t("security.scenarios.tabs.calibration") }));
  const facts = await screen.findByRole("region", { name: t("security.scenarios.readiness.title") });
  expect(within(facts).getByText(locale === "ru" ? "12 оценок" : "12 assessments")).toBeTruthy();
  expect(facts.textContent).toContain("future-state");
  expect(facts.textContent).toContain("future-gap");
  expect(facts.textContent).toContain(t("security.scenarios.readiness.fpr_not_measured", { decisive: 3, min: 10 }));
  if (locale === "en") expect(facts.textContent).not.toMatch(/[А-Яа-яЁё]/);
  expect(state.review).not.toHaveBeenCalled();
});

it("opens Sigma source discovery without another workspace's execution state or an admission write", async () => {
  state.scenarios.mockResolvedValue(workspace());
  await mount();
  await screen.findByRole("heading", { name: scenario.title, level: 2 });
  await userEvent.click(screen.getByRole("button", { name: "Проверки Sigma" }));
  expect(screen.getByRole("heading", { name: t("security.sigma.list.title") })).toBeTruthy();
  await waitFor(() => expect(state.sigmaRules).toHaveBeenCalledExactlyOnceWith(undefined));
  expect(state.admission).not.toHaveBeenCalled();
  expect(screen.queryByRole("heading", { name: scenario.title, level: 2 })).toBeNull();
  expect(screen.queryByLabelText("Окно калибровки")).toBeNull();
  expect(screen.queryByText("Контур активен")).toBeNull();
  expect(state.calibration).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Сценарии" }));
  expect(await screen.findByRole("heading", { name: scenario.title, level: 2 })).toBeTruthy();
});

it("continues scenarios with the server cursor and resets on a filter change", async () => {
  state.scenarios.mockImplementation((params: URLSearchParams) => Promise.resolve(params.has("cursor")
    ? workspace({ items: [{ ...scenario, scenario_id: "sc-2", title: "Synthetic next scenario" }] })
    : workspace({ has_more: true, next_cursor: "scenarios-next" })));
  await mount();
  await userEvent.click(await screen.findByRole("button", { name: "Показать следующие сценарии" }));
  expect(await screen.findByRole("heading", { name: "Synthetic next scenario", level: 2 })).toBeTruthy();
  expect(screen.getByRole("heading", { name: scenario.title, level: 2 })).toBeTruthy();
  expect(String(state.scenarios.mock.calls[1][0])).toBe("limit=30&cursor=scenarios-next");
  await userEvent.selectOptions(screen.getByLabelText("Риск"), "high");
  await waitFor(() => expect(screen.queryByRole("heading", { name: "Synthetic next scenario", level: 2 })).toBeNull());
  expect(String(state.scenarios.mock.lastCall![0])).toBe("risk_class=high&limit=30");
});

it("continues exact evidence and keeps the first page when continuation fails", async () => {
  state.scenarios.mockImplementation((params: URLSearchParams) => params.has("evidence_cursor")
    ? Promise.reject(new ApiResponseError(503))
    : Promise.resolve(workspace({ items: [{ ...scenario, evidence_has_more: true, evidence_next_cursor: "evidence-next" }] })));
  await mount();
  await userEvent.click(await screen.findByRole("button", { name: "Показать следующие доказательства" }));
  expect(await screen.findByText("Продолжение не загружено. Повторите попытку.")).toBeTruthy();
  expect(screen.getByRole("link", { name: "Событие DB 517548" })).toBeTruthy();
  state.scenarios.mockResolvedValue(workspace({ items: [{ ...scenario, evidence: [{ normalized_event_id: "next", event_db_id: 517550, evidence_order: 2 }], evidence_has_more: false }] }));
  await userEvent.click(screen.getByRole("button", { name: "Показать следующие доказательства" }));
  expect(await screen.findByRole("link", { name: "Событие DB 517550" })).toBeTruthy();
  expect(screen.getByRole("link", { name: "Событие DB 517548" })).toBeTruthy();
  expect(String(state.scenarios.mock.lastCall![0])).toBe("scenario_id=sc-1&evidence_cursor=evidence-next&limit=1");
  expect(screen.queryByRole("button", { name: "Показать следующие доказательства" })).toBeNull();
});

it("renders scenarios with exact evidence links and the not-checked conclusion", async () => {
  state.scenarios.mockResolvedValue(workspace());
  await mount();
  expect(await screen.findByRole("heading", { name: "Блокировка учётной записи", level: 2 })).toBeTruthy();
  expect(screen.getByRole("link", { name: "Событие DB 517548" }).getAttribute("href")).toBe("/app/events/517548");
  expect(screen.getByText("Не проверено")).toBeTruthy();
  expect(String(state.scenarios.mock.calls[0][0])).toBe("limit=30");
  expect(state.actions).not.toHaveBeenCalled();
});

it("validates the rationale and posts the review form values", async () => {
  state.scenarios.mockResolvedValue(workspace());
  state.review.mockResolvedValue({ api_version: "v1", item: {}, replayed: false });
  await mount();
  const rationale = await screen.findByLabelText("Обоснование");
  const submit = screen.getByRole("button", { name: "Сохранить append-only оценку" }) as HTMLButtonElement;
  expect(submit.disabled).toBe(true);
  await userEvent.type(rationale, "abc");
  expect(submit.disabled).toBe(true);
  expect(state.review).not.toHaveBeenCalled();
  await userEvent.selectOptions(screen.getByLabelText("Вердикт"), "false_positive");
  await userEvent.selectOptions(screen.getByLabelText("Уверенность"), "high");
  await userEvent.type(rationale, "def ok");
  expect(submit.disabled).toBe(false);
  await userEvent.click(submit);
  await waitFor(() => expect(state.review).toHaveBeenCalledOnce());
  const [id, body] = state.review.mock.calls[0];
  expect(id).toBe("sc-1");
  expect(body).toMatchObject({ verdict: "false_positive", review_confidence: "high", rationale: "abcdef ok" });
  expect(typeof body.review_request_id).toBe("string");
  expect(await screen.findByText("Оценка сохранена и перечитана с сервера.")).toBeTruthy();
  expect(state.scenarios.mock.calls.length).toBeGreaterThan(1);
});

it("reports a rejected review and keeps writes closed when the review schema is not ready", async () => {
  state.scenarios.mockResolvedValue(workspace());
  state.review.mockRejectedValue(new ApiResponseError(500));
  await mount();
  await userEvent.type(await screen.findByLabelText("Обоснование"), "достаточно подробно");
  await userEvent.click(screen.getByRole("button", { name: "Сохранить append-only оценку" }));
  expect((await screen.findByText("Оценка не сохранена. Сценарий и существующие оценки не изменены.")).getAttribute("role")).toBe("alert");
  cleanup();
  state.scenarios.mockResolvedValue(workspace({ execution: execution({ analyst_review_schema_ready: false }) }));
  await mount();
  expect(((await screen.findByLabelText("Обоснование")) as HTMLInputElement).disabled).toBe(true);
  expect(screen.getByText(/Migration 33 ещё не применена/)).toBeTruthy();
});

it("never shows an unavailable or failed read as an empty list", async () => {
  state.scenarios.mockResolvedValue(workspace({ state: "unavailable", items: [] }));
  await mount();
  const unavailable = await screen.findByText(/Семантический контур сейчас недоступен/);
  expect(unavailable.closest("[data-state]")?.getAttribute("data-state")).toBe("unavailable");
  expect(screen.queryByText(/Сохранённых сценариев пока нет/)).toBeNull();
  cleanup();
  state.scenarios.mockRejectedValue(new ApiResponseError(403));
  await mount();
  const denied = await screen.findByText(/Семантический срез не прочитан/);
  expect(denied.closest("[data-state]")?.getAttribute("data-state")).toBe("denied");
});

it("shows a real empty state and switches to the calibration view", async () => {
  state.scenarios.mockResolvedValue(workspace({ state: "empty", items: [] }));
  state.calibration.mockResolvedValue({
    api_version: "v1", state: "available", window_hours: 24, execution: execution(),
    jobs: [{ evaluation_mode: "test", evaluation_status: "done", job_count: 4, attempts: 5, errors: 0 }], results: [], policies: [],
  });
  await mount();
  expect(await screen.findByText(/Сохранённых сценариев пока нет/)).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: "Калибровка" }));
  expect(await screen.findByText("Очередь оценок", { selector: "h2" })).toBeTruthy();
  expect(state.calibration).toHaveBeenCalledWith(24);
  expect(screen.getByText("Оценки за окно отсутствуют.")).toBeTruthy();
});

it("keeps service markers in a closed details block below the conclusions", async () => {
  state.scenarios.mockResolvedValue(workspace());
  await mount();
  const conclusion = await screen.findByRole("heading", { name: "Блокировка учётной записи", level: 2 });
  const details = screen.getByText("Технические сведения").closest("details")!;
  expect(details.hasAttribute("open")).toBe(false);
  expect(conclusion.compareDocumentPosition(details) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(details.textContent).toContain("Маркер runtime33");
  await userEvent.click(screen.getByText("Технические сведения"));
  expect(details.hasAttribute("open")).toBe(true);
});

it.each([[503, "ru"], [401, "ru"], [403, "ru"], [503, "en"], [401, "en"], [403, "en"]] as const)("reports cached scenarios refresh failure %s and conceals revoked data", async (status, locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  state.scenarios.mockResolvedValue(workspace());
  await mount(client); await screen.findByRole("heading", { name: scenario.title, level: 2 });
  state.scenarios.mockRejectedValue(new ApiResponseError(status));
  await act(() => client.invalidateQueries({ queryKey: ["semantic-scenarios"] }));
  await waitFor(() => expect(document.querySelector(`[data-state="${status === 503 ? "stale" : "denied"}"]`)).not.toBeNull());
  expect(Boolean(screen.queryByRole("heading", { name: scenario.title, level: 2 }))).toBe(status === 503);
  if (status === 503) expect(screen.getByText(t("security.scenarios.state.refreshFailed"))).toBeTruthy();
  if (status !== 503) {
    expect(screen.queryByRole("link", { name: /517548/ })).toBeNull();
    state.scenarios.mockRejectedValue(new ApiResponseError(503));
    await act(() => client.invalidateQueries({ queryKey: ["semantic-scenarios"] }));
    await waitFor(() => expect(document.querySelector('[data-state="unavailable"]')).not.toBeNull());
    expect(screen.queryByRole("heading", { name: scenario.title, level: 2 })).toBeNull();
    expect(client.getQueryCache().find({ queryKey: ["semantic-scenarios"], exact: false })?.state.data).toBeUndefined();
    await userEvent.selectOptions(screen.getByLabelText(t("security.scenarios.filters.risk")), "high");
    await userEvent.selectOptions(screen.getByLabelText(t("security.scenarios.filters.risk")), "");
    cleanup(); await mount(client);
    await waitFor(() => expect(document.querySelector('[data-state="unavailable"]')).not.toBeNull());
    expect(screen.queryByRole("heading", { name: scenario.title, level: 2 })).toBeNull();
    state.scenarios.mockResolvedValue(workspace());
    await act(() => client.invalidateQueries({ queryKey: ["semantic-scenarios"] }));
    expect(await screen.findByRole("heading", { name: scenario.title, level: 2 })).toBeTruthy();
  }
});

it.each([503, 403])("handles scenario continuation failure %s separately from refresh", async (status) => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  state.scenarios.mockImplementation((params: URLSearchParams) => params.has("cursor")
    ? Promise.reject(new ApiResponseError(status))
    : Promise.resolve(workspace({ has_more: true, next_cursor: "next" })));
  await mount(client);
  await userEvent.click(await screen.findByRole("button", { name: t("security.scenarios.continuation.scenarios") }));
  await waitFor(() => expect(document.querySelector('[data-state="denied"]') || screen.queryByText(t("security.scenarios.continuation.error"))).not.toBeNull());
  expect(Boolean(screen.queryByRole("heading", { name: scenario.title, level: 2 }))).toBe(status === 503);
  expect(document.querySelector('[data-state="stale"]')).toBeNull();
  if (status === 403) {
    expect(screen.queryByRole("button", { name: t("security.scenarios.continuation.scenarios") })).toBeNull();
    expect(screen.queryByText(t("security.scenarios.execution.disabled"))).toBeNull();
    expect(document.querySelector('[data-state="partial"]')).toBeNull();
    state.scenarios.mockRejectedValue(new ApiResponseError(503));
    await act(() => client.invalidateQueries({ queryKey: ["semantic-scenarios"] }));
    await waitFor(() => expect(document.querySelector('[data-state="unavailable"]')).not.toBeNull());
    expect(screen.queryByRole("heading", { name: scenario.title, level: 2 })).toBeNull();
    expect(document.querySelector('[data-state="stale"]')).toBeNull();
  }
});

it.each(["ru", "en"] as const)("labels result classes independently of risk and submits exact values (%s)", async (locale) => {
  const reload = vi.spyOn(localeRuntime, "reload").mockImplementation(() => {});
  setLocale(locale);
  try {
  state.scenarios.mockResolvedValue(workspace());
  await mount();
  const result = await screen.findByLabelText(locale === "ru" ? "Класс результата" : "Result class");
  const expected = [
    ["security_incident", locale === "ru" ? "Инцидент" : "Incident"],
    ["security_exposure", locale === "ru" ? "Экспозиция" : "Exposure"],
    ["control_gap", locale === "ru" ? "Пробел контроля" : "Control gap"],
  ];
  for (const [value, label] of expected) {
    expect(result.querySelector(`option[value="${value}"]`)?.textContent).toBe(label);
    await userEvent.selectOptions(result, value);
    await waitFor(() => expect(String(state.scenarios.mock.lastCall![0])).toBe(`result_class=${value}&limit=30`));
  }
  await userEvent.selectOptions(screen.getByLabelText(locale === "ru" ? "Риск" : "Risk"), "critical");
  await waitFor(() => expect(String(state.scenarios.mock.lastCall![0])).toBe("result_class=control_gap&risk_class=critical&limit=30"));
  } finally { setLocale("ru"); reload.mockRestore(); }
});

it.each(["ru", "en"] as const)("formats the completeness observation in %s, leaving its UTC evidence intact", async (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
  const captured = "2026-10-21T14:05:00Z";
  const snapshot = { captured_at_utc: captured };
  state.scenarios.mockResolvedValue(workspace({ items: [{ ...scenario, completeness_snapshot: snapshot }] }));
  await mount();
  expect(await screen.findByText(t("security.scenarios.completeness.snapshot", { time: locale === "ru" ? "21.10.2026, 14:05" : "Oct 21, 2026, 2:05 PM" }))).toBeTruthy();
  expect(snapshot.captured_at_utc).toBe(captured);
});
