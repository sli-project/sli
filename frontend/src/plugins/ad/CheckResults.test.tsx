// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import type { ReportResultDto } from "../../api/report-v2-types";
import { localeRuntime, setLocale } from "../../i18n";
import { ComputerChecks } from "./ComputerChecks";

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
    <ComputerChecks result={result} onSelect={vi.fn()} onInventory={vi.fn()}/>
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

it("labels the first computer assessment in the selected language", () => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  const result = page([{ key: "first", title: "First check", total: 1, new_count: null,
    status: "no_comparison", status_text: "Нет сравнения с прошлым снимком" }]);
  for (const [locale, expected] of [["ru", "Первая проверка"], ["en", "First check"]] as const) {
    setLocale(locale);
    const { container, unmount } = render(<QueryClientProvider client={new QueryClient()}>
      <ComputerChecks result={result} onSelect={vi.fn()} onInventory={vi.fn()}/>
    </QueryClientProvider>);
    expect(container.querySelector(".sli-ds-review-list__status")?.textContent).toBe(expected);
    expect(container.textContent).not.toContain("Нет сравнения с прошлым снимком");
    unmount();
  }
});
