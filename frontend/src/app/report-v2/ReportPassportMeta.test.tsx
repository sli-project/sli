// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { ReportIntentDto, ReportResultDto } from "../../api/report-v2-types";
import { localeRuntime, setLocale, t } from "../../i18n";
import { ReportPassportMeta } from "./ReportPassportMeta";

const intent: ReportIntentDto = {
  contract_id: "sli.report-intent.v1", version: 1, user_role: "Reviewer",
  question: "Which observations need review?", action: "Inspect evidence", scope: "Granted scope",
  exclusions: "No inferred activity", sources: ["Canonical observations"],
  freshness_expectation: "Last confirmed source observation", rights: "Server grant",
  field_classes: ["security"], coverage: "Expected sources and window",
  completeness: "Confirmed source continuity", denominator: "Expected sources × period",
  retention: "Bounded raw evidence", provenance: "Exact source observation ID", primary_archetype: "timeline",
};

beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("ru");
  vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-10-08T00:00:00Z"));
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); });

function header(coverage?: ReportResultDto["coverage"], state: "ok" | "empty" | "partial" | "stale" = "ok") {
  return render(<ReportPassportMeta intent={intent} coverage={coverage} state={state} timeZone="UTC"/>).container;
}

it.each(["ru", "en"] as const)("shows a dated status line and closed details (%s)", (locale) => {
  setLocale(locale);
  const element = header({ observed_at_utc: "2026-09-15T00:00:00Z", completeness: "not_proven" });
  const disclosure = screen.getByText(t("reports.passport.more")).closest("details")!;
  expect(disclosure.open).toBe(false);
  const line = element.querySelector("span")!;
  expect(line.textContent).toContain(locale === "ru" ? "23 дня назад" : "23 days ago");
  expect(line.textContent).toContain("2026");
  expect(element.textContent).not.toMatch(/Полнота|Completeness/i);
  expect(line.textContent).not.toContain(intent.denominator);
  expect(disclosure.textContent).not.toContain(intent.denominator);
  expect(disclosure.textContent).toContain(intent.freshness_expectation);
  fireEvent.click(screen.getByText(t("reports.passport.more")));
  expect(disclosure.open).toBe(true);
});

it.each(["not_proven", "future_value", "partial", "complete"] as const)("shows no completeness label for %s", (completeness) => {
  const element = header({ observed_at_utc: "2026-09-15T00:00:00Z", completeness });
  expect(element.textContent).not.toMatch(/Полнота|Completeness/i);
  expect(element.querySelector("span [data-tone]")).toBeNull();
});

it.each([undefined, null, "invalid", "", 42])("omits unknown source time %s", (observed_at_utc) => {
  const element = header({ observed_at_utc });
  expect(element.textContent).not.toMatch(/неизвестно|unknown/i);
  expect(element.textContent).not.toContain(t("reports.passport.observed", { value: "" }).trim());
});

it("does not use response time, history bounds or completeness state as source confirmation", () => {
  const element = header({ state: "complete", generated_at_utc: "2026-10-07T00:00:00Z", history_to_utc: "2026-10-07T00:00:00Z" });
  expect(element.textContent).not.toContain("2026");
  expect(element.textContent).not.toMatch(/Полнота|Completeness/i);
});

it("omits blank measurement definitions instead of showing empty labels", () => {
  const { container } = render(<ReportPassportMeta intent={{ ...intent, denominator: " ", freshness_expectation: "" }} state="ok"/>);
  expect(container.textContent).not.toContain(t("reports.passport.expectation", { value: "" }).trim());
});

it("keeps all known clocks and historical state inside the disclosure", () => {
  const element = header({ event_at_utc: "2026-09-01T00:00:00Z", snapshot_at_utc: "2026-09-02T00:00:00Z", published_at_utc: "2026-10-07T00:00:00Z" }, "stale");
  const disclosure = element.querySelector("details")!;
  for (const key of ["event", "snapshot", "published"] as const) {
    expect(disclosure.textContent).toContain(t(`reports.freshness.${key}`, { time: "" }).trim());
  }
  expect(disclosure.textContent).toContain(t("reports.passport.stale"));
  expect(element.querySelector("span")!.textContent).not.toContain("07.10.2026");
});


it.each(["ru", "en"] as const)("keeps static description in details and shows no completeness label (%s)", (locale) => {
  setLocale(locale);
  const { container } = render(<ReportPassportMeta intent={intent} coverage={{ completeness: "not_proven" }}
    state="partial" description="Synthetic report description"/>);
  expect(screen.getByText("Synthetic report description").closest("details")?.open).toBe(false);
  expect(container.textContent).not.toMatch(/Полнота|Completeness/i);
  expect(container.querySelectorAll("details")).toHaveLength(1);
});
