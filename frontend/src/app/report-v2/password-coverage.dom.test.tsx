// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import { ReportRenderer } from "./ReportRenderer";
import { localeRuntime, setLocale } from "../../i18n";

const definition: ReportDefinitionDto = {
  key: "security.problems", section: "investigation", title: "Synthetic queue", description: "Synthetic report", archetype: "queue",
  params: [], columns: [{ key: "id", label: "ID", kind: "text", path: "id" }],
  views: [{ kind: "table", key: "table" }], row_key: "id", detail: "none", export: false,
  limits: { default: 50, max: 200 }, presets: [], row_links: [], filter_options: {},
};
const page = (state: ReportResultDto["state"] = "partial"): ReportResultDto => ({
  contract_id: "sli.report-result.v2", report_key: definition.key, state, items: [],
  has_more: false, next_cursor: null, filtered_count: 0, metrics: [], series: {}, filter_options: {},
  limitations: [], window: {}, coverage: { password_detection: {
    availability: "observed", as_of: "2026-10-20T00:00:00.000000Z", rows: [], has_more: false,
  } },
});
beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });
afterEach(() => { cleanup(); setLocale("ru"); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

function renderReport(body: ReportResultDto, key = definition.key) {
  window.history.replaceState(null, "", "/app/report/security.problems");
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(
    JSON.stringify(String(input).includes("/data?") ? body : { ...definition, key }),
    { headers: { "Content-Type": "application/json" } },
  )));
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <ReportRenderer reportKey={key}/></QueryClientProvider>);
}

it.each(["ru", "en"] as const)("shows one empty state without a coverage block in %s", async (locale) => {
  setLocale(locale);
  const { container } = renderReport(page("empty"));
  await waitFor(() => expect(container.querySelectorAll(".sli-ds-state")).toHaveLength(1));
  expect(screen.queryByRole("region", { name: /покрыти|coverage/i })).toBeNull();
  expect(container.querySelector('[data-state="empty"]')).toBeTruthy();
  expect(screen.queryByRole("table")).toBeNull();
});

const scopeRow = {
  domain_id: "7", rule_id: "qw.password-brute-force" as const, scope_ref: "a".repeat(64),
  policy_state: "enabled" as const, status: "partial" as const, reason: "too_late" as const,
  last_attempt_at: "2026-10-20T00:00:00.000000Z", last_completed_at: "2026-10-20T00:00:00.000000Z",
  last_successful_cutoff: "2026-10-19T23:58:00Z", frozen_episode_count: "0", evidence_snapshot_as_of: null,
  loss: {},
};

it.each(["ru", "en"] as const)("keeps frozen coverage details off an empty report in %s", async (locale) => {
  setLocale(locale);
  const body = page("empty");
  body.coverage.password_detection!.rows = [{ ...scopeRow, status: "frozen", frozen_episode_count: "1",
    evidence_snapshot_as_of: "2026-10-18T10:00:00Z", loss: { too_late: {
      count_lower_bound: "9007199254740993", count_exact: false,
      from: "2026-10-19T20:00:00Z", to: "2026-10-19T23:00:00Z",
      observation_window_from: "2026-10-19T20:00:00Z", as_of: "2026-10-20T00:00:00.000000Z",
    } } }];
  const { container } = renderReport(body);
  await waitFor(() => expect(container.querySelectorAll(".sli-ds-state")).toHaveLength(1));
  expect(container.textContent).not.toContain("9007199254740993");
  expect(screen.queryByRole("region", { name: /покрыти|coverage/i })).toBeNull();
});

it.each(["ru", "en"] as const)("keeps disabled coverage details off an empty report in %s", async (locale) => {
  setLocale(locale);
  const body = page("empty");
  body.coverage.password_detection!.rows = [{ ...scopeRow, policy_state: "disabled" }];
  const { container } = renderReport(body);
  await waitFor(() => expect(container.querySelectorAll(".sli-ds-state")).toHaveLength(1));
  expect(screen.queryByRole("region", { name: /покрыти|coverage/i })).toBeNull();
  expect(container.querySelector('[data-state="empty"]')).toBeTruthy();
});

it("never renders coverage from a denied response or a different report", async () => {
  const body = page("denied");
  body.coverage.password_detection!.rows = [{ ...scopeRow, scope_ref: "secret-unallowed-scope" }];
  renderReport(body);
  await screen.findByRole("heading", { level: 1 });
  expect(screen.queryByRole("region", { name: /покрыти|coverage/i })).toBeNull();
  expect(document.body.textContent).not.toContain("secret-unallowed-scope");
  cleanup();
  body.state = "empty";
  body.report_key = "demo.events";
  renderReport(body, "demo.events");
  await screen.findByRole("heading", { level: 1 });
  expect(screen.queryByRole("region", { name: /покрыти|coverage/i })).toBeNull();
});


it.each([
  ["ru", "empty"], ["en", "empty"], ["ru", "ok"], ["en", "ok"],
] as const)("keeps findings visible without disabled frozen coverage in %s from %s", async (locale, initialState) => {
  setLocale(locale);
  const body = page(initialState);
  if (initialState === "ok") {
    body.items = [{ id: "retained-finding" }];
    body.filtered_count = 1;
  }
  body.coverage.password_detection!.rows = [{ ...scopeRow, policy_state: "disabled", status: "frozen",
    frozen_episode_count: "2", evidence_snapshot_as_of: "2026-10-18T10:00:00Z" }];
  const { container } = renderReport(body);
  if (initialState === "ok") await screen.findByText("retained-finding");
  else await waitFor(() => expect(container.querySelectorAll(".sli-ds-state")).toHaveLength(1));
  expect(screen.queryByRole("region", { name: /покрыти|coverage/i })).toBeNull();
  expect(container.textContent).not.toContain("Frozen episodes");
  expect(container.textContent).not.toContain("Заморожено эпизодов");
  if (initialState === "ok") expect(screen.getByRole("table").textContent).toContain("retained-finding");
  else expect(container.querySelectorAll(".sli-ds-state")).toHaveLength(1);
});
