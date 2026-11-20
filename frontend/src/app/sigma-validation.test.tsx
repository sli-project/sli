// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { SigmaHistoryExecution, SigmaValidationResponse, SigmaValidationRule } from "../api/sigma-types";
import { ApiResponseError } from "../api/client";
import { localeRuntime, setLocale, t } from "../i18n";
import { en } from "../i18n/en";
import { ru } from "../i18n/ru";

const state = vi.hoisted(() => ({ read: vi.fn() }));
vi.mock("../api/client", async (importOriginal) => ({
  ...await importOriginal<typeof import("../api/client")>(),
  api: { sigmaValidation: (params: unknown) => state.read(params) },
}));
import { SigmaValidationPanel } from "./sigma-validation";

const scope = { installation_id: "00000000-0000-0000-0000-000000000001", plugin_id: "sli.ad",
  source_instance_id: "fixture-source", source_generation: "fixture-generation", collection_scope_id: "" };
const execution: SigmaHistoryExecution = {
  manifest_sha256: "b".repeat(64), plan_sha256: "c".repeat(64), compiler_version: "compiler-v1",
  mapping_version: "mapping-v1", overlay_sha256: null, mode: "test", state: "no_matches", complete: true,
  counts: { scanned: 10, evaluable: 10, matched: 0, suppressed: 0, unknown: 0, skipped: 0 },
  evaluable_percent: 100, matches_per_1000_evaluable: 0, required_fields: ["CommandLine"],
  evaluation_intervals: [{ since: "2026-01-01T00:00:00Z", until: "2026-01-02T00:00:00Z" }],
  quality: [{ since: "2026-01-01T00:00:00Z", until: "2026-01-02T00:00:00Z", status: "completed", reasons: [], unknown_fields: [] }],
};
function rule(overrides: Partial<SigmaValidationRule> = {}): SigmaValidationRule {
  return { rule_id: "00000000-0000-0000-0000-000000000002", raw_sha256: "a".repeat(64), upstream_commit: "d".repeat(40),
    compile_state: "supported", fixture_validation: "not_checked", current_admission: "not_measured", executions: [execution], ...overrides };
}
function response(rules = [rule()]): SigmaValidationResponse {
  return { api_version: "v1", contract: "sli.sigma.attack-coverage.v1", read_only: true,
    scope, since: "2026-01-01T00:00:00Z", until: "2026-01-02T00:00:00Z", state: "available", reason: null, rules };
}
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(<QueryClientProvider client={client}><SigmaValidationPanel/></QueryClientProvider>);
}
function fillScope() {
  const values = { ...scope, catalog_sha256: "e".repeat(64), since: "2026-01-01T00:00", until: "2026-01-02T00:00" };
  for (const [key, value] of Object.entries(values)) fireEvent.change(document.getElementById(`sigma-${key}`)!, { target: { value } });
}
function submit() { fireEvent.click(screen.getByRole("button", { name: t("security.sigma.load") })); }

beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("ru");
  state.read.mockResolvedValue(response());
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); vi.resetAllMocks(); });

it("reads only an explicitly selected scope, using UTC boundaries and no mutation", async () => {
  mount();
  expect(state.read).not.toHaveBeenCalled();
  expect((screen.getByRole("button", { name: t("security.sigma.load") }) as HTMLButtonElement).disabled).toBe(true);
  fillScope(); submit();
  await screen.findByRole("table");
  expect(state.read).toHaveBeenCalledExactlyOnceWith({ ...scope, catalog_sha256: "e".repeat(64),
    since: "2026-01-01T00:00:00.000Z", until: "2026-01-02T00:00:00.000Z" });
  expect(screen.getByText(t("security.sigma.boundary"))).toBeTruthy();
  fireEvent.change(screen.getByLabelText(t("security.sigma.scope.source"), { selector: "input" }), { target: { value: "fixture-other-source" } });
  expect(screen.queryByRole("table")).toBeNull();
  expect(state.read).toHaveBeenCalledTimes(1);
  submit();
  await waitFor(() => expect(state.read).toHaveBeenCalledTimes(2));
  expect(state.read.mock.lastCall![0].source_instance_id).toBe("fixture-other-source");
});

it("does not accept a reversed or over-seven-day window or an invalid catalog pin", () => {
  mount(); fillScope();
  const button = screen.getByRole("button", { name: t("security.sigma.load") }) as HTMLButtonElement;
  for (const until of ["2025-12-31T00:00", "2026-01-01T00:00", "2026-01-09T00:00"]) {
    fireEvent.change(document.getElementById("sigma-until")!, { target: { value: until } });
    expect(button.disabled).toBe(true);
  }
  fillScope();
  fireEvent.change(document.getElementById("sigma-catalog_sha256")!, { target: { value: "unversioned" } });
  expect(button.disabled).toBe(true);
  expect(state.read).not.toHaveBeenCalled();
});

it("keeps blocked and unchecked revisions distinct from a zero match count", async () => {
  state.read.mockResolvedValue(response([
    rule({ compile_state: "unsupported", executions: [] }),
    rule({ rule_id: "00000000-0000-0000-0000-000000000003", compile_state: "not_checked", executions: [] }),
  ]));
  mount(); fillScope(); submit();
  const table = await screen.findByRole("table");
  expect(within(table).getByText(t("security.sigma.state.blocked"))).toBeTruthy();
  expect(within(table).getByText(t("security.sigma.reason.unsupported"))).toBeTruthy();
  expect(within(table).getByText(t("security.sigma.reason.no_history"))).toBeTruthy();
  expect(within(table).queryByText("0")).toBeNull();
  expect(within(table).queryByText(t("security.sigma.state.no_matches"))).toBeNull();
});

it.each(["no_data", "no_matches", "matched", "degraded", "not_evaluable", "incomplete"] as const)("shows the server history state %s without upgrading validation", async (status) => {
  state.read.mockResolvedValue(response([rule({ executions: [{ ...execution, state: status }] })]));
  mount(); fillScope(); submit();
  const table = await screen.findByRole("table");
  expect(within(table).getByText(t(`security.sigma.state.${status}`))).toBeTruthy();
});

it("shows non-evaluable reasons, fields, failed/partial/cancelled intervals and unmeasured rates", async () => {
  state.read.mockResolvedValue(response([rule({ executions: [{ ...execution, state: "incomplete", complete: false,
    counts: { scanned: 10, evaluable: 0, matched: 0, unknown: 8, skipped: 2, suppressed: 0 },
    evaluable_percent: 0, matches_per_1000_evaluable: null,
    quality: ["failed", "partial", "cancelled"].map((status) => ({ ...execution.quality[0], status,
      reasons: [["payload_unavailable", 2]], unknown_fields: [["CommandLine", "field_unavailable", 8]] })),
  }] })]));
  mount(); fillScope(); submit();
  const table = await screen.findByRole("table");
  expect(within(table).getAllByText(/CommandLine/).length).toBeGreaterThan(0);
  expect(within(table).getAllByText(new RegExp(t("security.sigma.reason.payload"))).length).toBe(3);
  expect(within(table).getAllByText(new RegExp(t("security.sigma.reason.field_unavailable"))).length).toBe(3);
  for (const status of ["failed", "partial", "cancelled"]) expect(table.textContent).toContain(t(`security.sigma.status.${status}` as keyof typeof ru));
  const rate = within(table).getByText(t("security.sigma.noise")).parentElement!;
  expect(rate.textContent).toContain(t("security.sigma.unmeasured"));
});

it("keeps execution versions separate and displays their full pins", async () => {
  state.read.mockResolvedValue(response([rule({ executions: [execution,
    { ...execution, mapping_version: "mapping-v2", plan_sha256: "f".repeat(64), overlay_sha256: "1".repeat(64) }] })]));
  mount(); fillScope(); submit();
  const table = await screen.findByRole("table");
  expect(within(table).getAllByRole("row")).toHaveLength(3);
  expect(table.textContent).toContain("mapping-v1");
  expect(table.textContent).toContain("mapping-v2");
  expect(table.textContent).toContain("f".repeat(64));
  expect(table.textContent).toContain("1".repeat(64));
});

it.each(["source_unavailable_or_denied", "catalog_unavailable", "projection_limit", "projection_unavailable"])("shows %s as unavailable even if stale rows are present", async (reason) => {
  state.read.mockResolvedValue({ ...response(), state: "unavailable", reason });
  mount(); fillScope(); submit();
  expect(await screen.findByRole("alert")).toBeTruthy();
  expect(screen.queryByRole("table")).toBeNull();
  expect(screen.queryByText(t("security.sigma.state.no_matches"))).toBeNull();
});

it("shows denied access and hides untrusted error text", async () => {
  state.read.mockRejectedValue(new ApiResponseError(403));
  mount(); fillScope(); submit();
  const alert = await screen.findByRole("alert");
  expect(alert.getAttribute("data-state")).toBe("denied");
  expect(screen.queryByRole("table")).toBeNull();
});

it("retries an unavailable read and keeps an empty registry distinct from zero matches", async () => {
  state.read.mockRejectedValueOnce(new Error("fixture-private-error")).mockResolvedValueOnce(response([]));
  mount(); fillScope(); submit();
  await screen.findByRole("alert");
  expect(screen.queryByText("fixture-private-error")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: t("state.retry") }));
  expect(await screen.findByText(t("security.sigma.no_rules"))).toBeTruthy();
  expect(screen.queryByRole("table")).toBeNull();
});

it.each(["ru", "en"] as const)("renders localized results and unknown reasons in %s with identical keys", async (locale) => {
  const keys = (dictionary: Record<string, string>) => Object.keys(dictionary).filter((key) => key.startsWith("security.sigma.")).sort();
  expect(keys(ru)).toEqual(keys(en));
  setLocale(locale);
  state.read.mockResolvedValue({ ...response(), state: "unavailable", reason: "fixture-private-reason" });
  mount(); fillScope(); submit();
  expect(await screen.findByText(t("security.sigma.reason.unknown"))).toBeTruthy();
  expect(screen.queryByText("fixture-private-reason")).toBeNull();
  expect(document.body.textContent).not.toContain("security.sigma.");
});
