// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import type { ReportResultDto } from "../../api/report-v2-types";
import { localeRuntime, setLocale } from "../../i18n";
import { ComputerChecks } from "./ComputerChecks";
import { formatDateTime } from "../../shared/date-time";
import { DEFAULT_TIME_ZONE } from "../../shared/time-zone";

afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); });

const page = (items: Record<string, unknown>[]): ReportResultDto => ({
  contract_id: "sli.report-result.v2", report_key: "ad.computers.v6", state: "ok", items,
  filtered_count: items.length, has_more: false, next_cursor: null, metrics: [], series: {}, coverage: {},
  filter_options: {}, limitations: [], window: {},
});

it("omits unassessed computer checks while retaining zero and supplied counts", () => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("ru");
  const base = { severity: "medium", severity_text: "Средняя", status: "not_evaluated", status_text: "Не оценено", total: null, new_count: null };
  const result = page([
    { ...base, key: "missing", title: "Unassessed check" },
    { ...base, key: "missing-low", title: "Unassessed hygiene", severity: "low" },
    { ...base, key: "zero", title: "Zero check", total: 0 },
    { ...base, key: "observed", title: "Observed check", total: 4, new_count: 0, is_lower_bound: true },
    { ...base, key: "new", title: "New check", new_count: 2 },
  ]);
  const { container } = render(<QueryClientProvider client={new QueryClient()}>
    <ComputerChecks result={result} onSelect={vi.fn()} params="domain=8"/>
  </QueryClientProvider>);
  expect(screen.queryByText("Unassessed check")).toBeNull();
  expect(screen.queryByText("Unassessed hygiene")).toBeNull();
  expect(screen.getByText("Zero check").closest("summary")?.querySelector(".sli-ds-review-list__total")?.textContent).toBe("0");
  const observed = screen.getByText("Observed check").closest("summary")!;
  expect(observed.querySelector(".sli-ds-review-list__total")?.textContent).toBe("4");
  expect(observed.querySelector(".sli-ds-review-list__new")?.textContent).toBe("0");
  expect(screen.getByText("New check").closest("summary")?.querySelector(".sli-ds-review-list__new")?.textContent).toBe("2");
  expect(container.textContent).not.toContain("≥");
});

it("shows the date of an assessment without a comparison", () => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  const observed = "2026-11-13T12:00:00Z";
  const result = page([{ last_seen_utc: observed, key: "first", title: "First check", total: 1, new_count: null,
    status: "no_comparison", status_text: "Нет сравнения с прошлым снимком" }]);
  for (const locale of ["ru", "en"] as const) {
    setLocale(locale);
    const { container, unmount } = render(<QueryClientProvider client={new QueryClient()}>
      <ComputerChecks result={result} onSelect={vi.fn()} params="domain=8"/>
    </QueryClientProvider>);
    expect(container.querySelector(".sli-ds-review-list__status")?.textContent).toBe(formatDateTime(observed, DEFAULT_TIME_ZONE));
    expect(container.textContent).not.toContain("Нет сравнения с прошлым снимком");
    unmount();
  }
});
