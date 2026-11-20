// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { ReportResultDto } from "../../api/report-v2-types";
import { localeRuntime, setLocale, t } from "../../i18n";
import { PairsWindowState } from "./PairsWindowState";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); });

const result: ReportResultDto = {
  contract_id: "sli.report-result.v2", report_key: "ad.new-logon-pairs", state: "partial",
  items: [], metrics: [], series: {}, filter_options: {}, limitations: [], has_more: false, next_cursor: null, filtered_count: 0,
  window: { from_utc: "2026-10-06T00:00:00Z", to_utc_exclusive: "2026-10-07T00:00:00Z" },
  coverage: { baseline_from_utc: "2026-09-06T00:00:00Z", baseline_to_utc_exclusive: "2026-10-06T00:00:00Z",
    history_from_utc: "2026-10-01T00:00:00Z", history_to_utc: "2026-10-05T00:00:00Z",
    baseline_history_covered: false, period_covered: false, baseline_truncated: true, period_truncated: false },
};

it.each(["ru", "en"] as const)("explains both windows and offers explicit recovery for a partial empty result (%s)", (locale) => {
  setLocale(locale);
  const latest = vi.fn();
  const baseline = vi.fn();
  render(<PairsWindowState result={result} onShowLatest={latest} onChangeBaseline={baseline}/>);
  const status = screen.getByRole("status");
  expect(status.textContent).toContain(t("reports.pairs.window.truncated"));
  expect(status.textContent).toContain(t("reports.pairs.window.missing"));
  expect(status.textContent).toContain(locale === "ru" ? "06.09.2026" : "Sep 6, 2026");
  expect(status.textContent).toContain(locale === "ru" ? "05.10.2026" : "Oct 5, 2026");
  expect(status.textContent).toContain(t("reports.pairs.recovery_note"));
  fireEvent.click(screen.getByRole("button", { name: t("reports.pairs.show_latest") }));
  fireEvent.click(screen.getByRole("button", { name: t("reports.pairs.change_baseline") }));
  expect(latest).toHaveBeenCalledTimes(1);
  expect(baseline).toHaveBeenCalledTimes(1);
});

it("keeps partial observations and identifies the current-window limit separately", () => {
  render(<PairsWindowState result={{ ...result, items: [{ id: "synthetic-pair" }], coverage: {
    ...result.coverage, baseline_history_covered: true, baseline_truncated: false, period_truncated: true,
  } }} onChangeBaseline={vi.fn()}/>);
  expect(screen.getByRole("status").textContent).toContain(t("reports.pairs.window.available"));
  expect(screen.getByRole("status").textContent).toContain(t("reports.pairs.window.truncated"));
  expect(screen.queryByRole("button", { name: t("reports.pairs.show_latest") })).toBeNull();
});

it("does not infer window coverage from absent metadata", () => {
  render(<PairsWindowState result={{ ...result, coverage: {} }} onChangeBaseline={vi.fn()}/>);
  expect(screen.getAllByText(new RegExp(t("reports.pairs.window.unknown")))).toHaveLength(2);
  expect(screen.queryByText(t("reports.pairs.window.available"), { exact: false })).toBeNull();
});

it.each(["denied", "error", "processing", "ok"] as const)("does not offer recovery for %s", (state) => {
  const { container } = render(<PairsWindowState result={{ ...result, state }} onShowLatest={vi.fn()} onChangeBaseline={vi.fn()}/>);
  expect(container.textContent).toBe("");
});
