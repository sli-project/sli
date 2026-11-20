// @vitest-environment jsdom
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { SemanticQueueOverview } from "../../api/client";
import { localeRuntime, setLocale } from "../../i18n";
import { SemanticQueueMetrics } from "./semantic-queue-metrics";

const queues = (): SemanticQueueOverview => ({
  status: "ok",
  window_seconds: 3600,
  warning_thresholds: { depth: 1000, oldest_pending_age_seconds: 900 },
  stages: [
    { queue_name: "processing", depth: 1000, oldest_pending_age_seconds: 899, completed_last_hour: 42 },
    { queue_name: "dispatch", depth: 999, oldest_pending_age_seconds: 900, completed_last_hour: 23 },
    { queue_name: "risk", depth: 0, oldest_pending_age_seconds: 0, completed_last_hour: 11 },
  ],
});

beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("ru");
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); });

it("shows all stages and hourly throughput with inclusive warning thresholds", () => {
  render(<SemanticQueueMetrics queues={queues()}/>);
  const table = screen.getByRole("table", { name: "Семантическая очередь по стадиям" });
  const processing = within(table).getByText("Нормализация").closest("tr")!;
  const dispatch = within(table).getByText("Диспетчеризация").closest("tr")!;
  const risk = within(table).getByText("Оценка риска").closest("tr")!;
  const processingCells = within(processing).getAllByRole("cell");
  const dispatchCells = within(dispatch).getAllByRole("cell");
  expect(processingCells[1].querySelector('[data-tone="warning"]')).toBeTruthy();
  expect(processingCells[2].querySelector('[data-tone="warning"]')).toBeNull();
  expect(processingCells[2].textContent).toBe("899 с");
  expect(processingCells[3].textContent).toBe("42");
  expect(dispatchCells[1].querySelector('[data-tone="warning"]')).toBeNull();
  expect(dispatchCells[2].querySelector('[data-tone="warning"]')).toBeTruthy();
  expect(dispatchCells[3].textContent).toBe("23");
  expect(within(risk).getByText("Нет ожидающих заданий")).toBeTruthy();
  expect(within(risk).getByText("11")).toBeTruthy();
  expect(risk.querySelector('[data-tone="warning"]')).toBeNull();
  expect(screen.getByText(/Предупреждение: от/).textContent).toContain("900 с");
});

it("uses thresholds supplied by the API", () => {
  const snapshot = queues();
  snapshot.warning_thresholds = { depth: 999, oldest_pending_age_seconds: 899 };
  render(<SemanticQueueMetrics queues={snapshot}/>);
  expect(screen.getByText("899 с").getAttribute("data-tone")).toBe("warning");
  expect(screen.getByText("999").getAttribute("data-tone")).toBe("warning");
});

it.each([
  undefined,
  { status: "unavailable" },
  { status: "ok", items: [] },
  { ...queues(), stages: queues().stages!.slice(0, 2) },
  { ...queues(), warning_thresholds: undefined },
  { ...queues(), window_seconds: 60 },
])("reports missing or unavailable metrics without inventing zeros: %j", (snapshot) => {
  render(<SemanticQueueMetrics queues={snapshot}/>);
  expect(screen.getByText("Метрики стадий семантической очереди недоступны.")).toBeTruthy();
  expect(screen.queryByRole("table")).toBeNull();
});

it("translates stage names, units and warning explanation into English", () => {
  setLocale("en");
  render(<SemanticQueueMetrics queues={queues()}/>);
  expect(screen.getByRole("table", { name: "Semantic queue by stage" })).toBeTruthy();
  for (const text of ["Normalization", "Dispatch", "Risk evaluation", "899 s", "No pending jobs", "Throughput over the last hour, jobs/h"]) {
    expect(screen.getByText(text)).toBeTruthy();
  }
  expect(screen.getByText(/Warning: at least/).textContent).toContain("900 s");
});
