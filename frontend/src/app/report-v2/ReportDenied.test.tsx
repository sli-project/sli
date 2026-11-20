// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, ApiResponseError, type V4Report } from "../../api/client";
import { OverlayProvider } from "../../design-system";
import { localeRuntime, setLocale, t } from "../../i18n";
import { ReportRenderer } from "./ReportRenderer";
import type { ReportDefinitionDto } from "../../api/report-v2-types";

const report: V4Report = {
  report_key: "workstations.logons", name: "Входы на станциях", version: 1,
  owner: "fixture", purpose: "fixture purpose", dataset_key: "workstations.security", dataset_version: 1,
  sensitivity: "restricted", status: "published", target_path: "/report/workstations.logons",
  allowed: false, explanation: "untranslated server text", explanation_code: "not_assigned", missing_capabilities: [],
  discoverable: true, requestable: true, access_state: "requestable", field_categories: [], allowed_actions: [],
  scopes: [], sources: [], grants: [], pinned: false, request_profile: { scope_kinds: ["all"] },
};

beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  vi.spyOn(api, "reportV2Definition").mockRejectedValue(new ApiResponseError(403, "report_access_denied"));
  vi.spyOn(api, "reportV2Data");
  vi.spyOn(api, "v4Reports").mockResolvedValue({ api_version: "v4", state: "ok", items: [report], allowed_count: 0, total_count: 1, explain_contract: "fixture" });
  vi.stubGlobal("scrollTo", vi.fn());
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><OverlayProvider><ReportRenderer reportKey="workstations.logons"/></OverlayProvider></QueryClientProvider>);
}

it.each(["ru", "en"] as const)("resolves the title and one denial reason from the user's catalogue (%s)", async (locale) => {
  setLocale(locale);
  mount();
  expect(await screen.findByRole("heading", { name: report.name })).toBeTruthy();
  expect(screen.getAllByText(t("reports.access.reason_not_assigned"))).toHaveLength(1);
  expect(screen.queryByText("untranslated server text")).toBeNull();
  expect(screen.queryByText(t("reports.states.denied.text"))).toBeNull();
  expect(screen.getByRole("link", { name: t("reports.access.own_rights") }).getAttribute("href")).toBe("/app/access-user");
  expect(screen.getByRole("link", { name: t("reports.catalog.page.title") }).getAttribute("href")).toBe("/app/reports");
  expect(screen.getByRole("button", { name: t("reports.catalog.action.request") })).toBeTruthy();
  expect(api.reportV2Data).not.toHaveBeenCalled();
});

it.each([
  { ...report, requestable: false, explanation_code: "explicit_deny" },
  { ...report, access_state: "request_pending" as const },
  { ...report, allowed: true },
])("offers no new request when it is unavailable or already pending", async (item) => {
  vi.mocked(api.v4Reports).mockResolvedValue({ api_version: "v4", state: "ok", items: [item], allowed_count: 0, total_count: 1, explain_contract: "fixture" });
  mount();
  await screen.findByRole("heading", { name: report.name });
  expect(screen.queryByRole("button", { name: t("reports.catalog.action.request") })).toBeNull();
});

it.each([
  ["explicit_deny", "reports.access.reason_explicit_deny"],
  ["missing_capabilities", "reports.access.reason_missing_capabilities"],
  ["version_review", "reports.access.reason_version_review"],
] as const)("explains the server's %s decision without technical filler", async (code, key) => {
  vi.mocked(api.v4Reports).mockResolvedValue({ api_version: "v4", state: "ok", items: [{ ...report, explanation_code: code }], allowed_count: 0, total_count: 1, explain_contract: "fixture" });
  mount();
  expect(await screen.findByText(t(key))).toBeTruthy();
});

it("preserves a resolved title and the specific reason when the data request is denied", async () => {
  const definition: ReportDefinitionDto = {
    key: report.report_key, section: "reports/workstations", title: report.name, description: "", archetype: "journal",
    params: [], columns: [], views: [{ key: "table", kind: "table" }], row_key: "id", detail: "none", export: false,
    limits: { default: 100, max: 500 }, presets: [], row_links: [], filter_options: {},
  };
  vi.mocked(api.reportV2Definition).mockResolvedValue(definition);
  vi.mocked(api.reportV2Data).mockRejectedValue(new ApiResponseError(403, "report_field_categories_not_allowed"));
  mount();
  expect(await screen.findByText(t("reports.access.denied_fields"))).toBeTruthy();
  expect(screen.queryByText(t("reports.access.reason_not_assigned"))).toBeNull();
  expect(screen.getByRole("heading", { name: report.name })).toBeTruthy();
  expect(screen.queryByText(t("reports.states.denied.text"))).toBeNull();
  expect(screen.getByRole("link", { name: t("reports.access.own_rights") })).toBeTruthy();
});

it.each(["private", "catalog_failed"])("keeps undisclosed metadata private and provides recovery links (%s)", async (kind) => {
  if (kind === "catalog_failed") vi.mocked(api.v4Reports).mockRejectedValue(new Error("fixture failure"));
  else vi.mocked(api.v4Reports).mockResolvedValue({ api_version: "v4", state: "ok", items: [], allowed_count: 0, total_count: 0, explain_contract: "fixture" });
  mount();
  await screen.findByRole("alert");
  expect(screen.getByRole("heading", { name: t("reports.renderer.default_title") })).toBeTruthy();
  expect(screen.queryByText(report.name)).toBeNull();
  expect(screen.queryByRole("button", { name: t("reports.catalog.action.request") })).toBeNull();
  expect(screen.getByRole("link", { name: t("reports.access.own_rights") })).toBeTruthy();
});

it("opens the existing request form and submits a request for the resolved report", async () => {
  const create = vi.spyOn(api, "v4CreateReportAccessRequest").mockResolvedValue({} as Awaited<ReturnType<typeof api.v4CreateReportAccessRequest>>);
  mount();
  await userEvent.click(await screen.findByRole("button", { name: t("reports.catalog.action.request") }));
  await userEvent.type(screen.getByLabelText(t("reports.catalog.drawer.reason")), "Synthetic review reason");
  await userEvent.click(screen.getByRole("button", { name: t("reports.catalog.drawer.send") }));
  await waitFor(() => expect(create).toHaveBeenCalledWith(expect.objectContaining({
    report_key: report.report_key, scope: { kind: "all" }, business_reason: "Synthetic review reason",
  })));
});
