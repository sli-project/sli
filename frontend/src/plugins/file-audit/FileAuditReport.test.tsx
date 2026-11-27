// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ApiResponseError } from "../../api/client";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import { FileAuditReport } from "./FileAuditReport";
import { t } from "../../i18n";
import reportDefinitions from "../../../../server-dotnet/src/Sli.Server/Reporting/V2/report-definitions.json";

const mocks = vi.hoisted(() => ({ definition: vi.fn(), data: vi.fn(), detail: vi.fn(), agents: vi.fn(), agentAction: vi.fn(), access: {
  platform_owner: false, preview: false,
  subject: { type: "user", id: 1, coarse_role: "viewer" }, evaluated_at_utc: "synthetic-evaluation", capabilities: ["file-audit.view", "file-audit.export"],
  reports: ["overview", "actions", "mass-operations", "permission-changes", "access-denials", "out-of-hours", "permissions", "audit-state"].map((key) => ({
    report_key: `file-audit.${key}`, allowed: true, allowed_actions: ["view", "export"], scopes: [] as Array<Record<string, unknown>>,
  })),
} }));
vi.mock("../../api/client", async (importOriginal) => ({ ...await importOriginal<typeof import("../../api/client")>(),
  api: { reportV2Definition: mocks.definition, reportV2Data: mocks.data, reportV2Detail: mocks.detail, agents: mocks.agents,
    agentAction: mocks.agentAction } }));
vi.mock("../../app/App", () => ({ useEffectiveAccess: () => mocks.access, useTimeZone: () => ({ timeZone: "UTC" }) }));
vi.mock("../../app/report-v2/ReportDenied", () => ({ ReportDenied: () => <div role="alert">Denied</div> }));

const declaration = (key = "file-audit.actions"): ReportDefinitionDto =>
  reportDefinitions.find(report => report.key === key)! as unknown as ReportDefinitionDto;
const result = (key: string, params: URLSearchParams): ReportResultDto => ({
  report_key: key, contract_id: "sli.report-result.v2", state: "ok",
  items: Array.from({ length: params.get("cursor") ? 2 : 50 }, (_, index) => ({ id: String(index), path: `Synthetic object ${params.get("cursor") ? index + 50 : index}` })),
  has_more: !params.get("cursor"), next_cursor: params.get("cursor") ? null : "synthetic-cursor",
  filtered_count: 52, metrics: [], series: {}, coverage: { state: "complete" }, filter_options: {}, limitations: [], window: { timezone: "UTC" },
});
let client: QueryClient;
function mount(initial = declaration()) {
  client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(<QueryClientProvider client={client}><FileAuditReport definition={initial}/></QueryClientProvider>);
}
beforeEach(() => {
  localStorage.clear();
  window.history.replaceState({}, "", "/app/report/file-audit.actions");
  mocks.definition.mockReset().mockImplementation(async (key: string) => declaration(key));
  mocks.data.mockReset().mockImplementation(async (key: string, params: URLSearchParams) => result(key, params));
  mocks.detail.mockReset();
  mocks.access.capabilities = ["file-audit.view", "file-audit.export"];
  mocks.access.platform_owner = false;
  mocks.access.preview = false;
  mocks.access.subject.coarse_role = "viewer";
  mocks.access.reports.forEach(report => { report.scopes = []; });
  mocks.agents.mockReset().mockResolvedValue({ items: [] });
  mocks.agentAction.mockReset().mockResolvedValue({ command_id: "new-check", policy_revision: 4, state: "pending" });
});
afterEach(() => { cleanup(); client?.clear(); vi.useRealTimers(); });

it("opens Actions by default and keeps the same period across the three views", async () => {
  mount();
  await screen.findByRole("table", { name: t("file-audit.screen.actions") });
  const actions = screen.getByRole("tab", { name: t("file-audit.screen.actions") });
  expect(actions.getAttribute("aria-selected")).toBe("true");
  expect(screen.queryByRole("tab", { name: t("file-audit.tabs.mass-operations") })).toBeNull();
  expect(screen.queryByRole("tab", { name: t("file-audit.tabs.audit-state") })).toBeNull();
  const from = mocks.data.mock.calls.at(-1)?.[1].get("from");
  await userEvent.click(screen.getByRole("tab", { name: t("file-audit.screen.overview") }));
  await screen.findByRole("table", { name: t("file-audit.screen.overview") });
  expect(mocks.data.mock.calls.at(-1)?.[1].get("from")).toBe(from);
  await userEvent.click(screen.getByRole("tab", { name: t("file-audit.screen.permissions") }));
  await screen.findByRole("table", { name: t("file-audit.screen.permissions") });
  expect(mocks.data.mock.calls.at(-1)?.[1].get("from")).toBe(from);
  expect(mocks.data.mock.calls.at(-1)?.[1].get("view")).not.toBe("objects");
  expect(screen.getAllByText(t("period.24h"), { selector: "summary span" })).toHaveLength(1);
});

it("gives the next action for empty Actions and Permissions tabs", async () => {
  mocks.data.mockImplementation(async (key, params) => ({ ...result(key, params),
    state: "partial", items: [], has_more: false, next_cursor: null, filtered_count: 0 }));
  mount();
  expect(await screen.findByText(t("file-audit.screen.empty_actions"))).toBeTruthy();
  await userEvent.click(screen.getByRole("tab", { name: t("file-audit.screen.permissions") }));
  expect(await screen.findByText(t("file-audit.screen.empty_permissions"))).toBeTruthy();
  expect(screen.queryByText(t("file-audit.screen.empty_actions"))).toBeNull();
});

it("shows the server's agent upgrade requirement on Resources", async () => {
  mocks.data.mockImplementation(async (key, params) => ({ ...result(key, params), items: [{
    id: "fixture-resource", share_name: "Fixture share", audit_receipt: {
      observed_at: "2026-11-26T08:00:00Z", state: "failed", reason_code: "native_unavailable",
      check_agent_requirement: { agent_version: "26.0.136", minimum_version: "26.0.154" },
    },
  }] }));
  mount(declaration("file-audit.overview"));
  const row = await screen.findByRole("row", { name: /Fixture share/ });
  expect(row.textContent).toContain(t("file-audit.screen.update_agent", { version: "26.0.136", minimum: "26.0.154" }));
  expect(row.textContent).not.toContain(t("file-audit.screen.audit_unreadable"));
});

it.each([
  ["coverage_incomplete", "file-audit.screen.inventory_incomplete"],
  ["sacl_missing", "file-audit.screen.sacl_missing"],
  ["policy_missing", "file-audit.screen.audit_policy_missing"],
] as const)("names the audit check that prevented collection (%s)", async (reason, message) => {
  mocks.data.mockImplementation(async (key, params) => ({ ...result(key, params), items: [{
    id: "fixture-resource", share_name: "Fixture share", audit_receipt: {
      action: "apply", observed_at: "2026-11-26T08:00:00Z", state: "partial", reason_code: reason,
    },
  }] }));
  mount(declaration("file-audit.overview"));
  const row = await screen.findByRole("row", { name: /Fixture share/ });
  expect(row.textContent).toContain(t(message));
  expect(row.textContent).not.toContain(t("file-audit.screen.no_batch"));
});

it("requests a check for the selected manageable resource and shows the fresh result", async () => {
  const target = { agent_id: "11111111-1111-4111-8111-111111111111", source_instance_id: "synthetic-source",
    collection_scope_id: "scope:files" };
  const observedAt = "2026-11-26T08:03:00Z";
  mocks.data.mockImplementation(async (key, params) => ({ ...result(key, params), items: [{
    id: "fixture-resource", share_name: "Fixture share", ...target, check_revision: 3,
    audit_receipt: { command_id: "old-check", state: "failed", reason_code: "native_unavailable", observed_at: "2026-11-26T08:00:00Z" },
    check_receipt: mocks.agentAction.mock.calls.length ? { state: "verified", observed_at: observedAt } : undefined,
  }, { id: "other-resource", share_name: "Other share", ...target, collection_scope_id: "scope:other" }] }));
  mount(declaration("file-audit.overview"));
  const row = within(await screen.findByRole("row", { name: /Fixture share/ }));
  expect(row.getByText(new RegExp(t("file-audit.screen.audit_unreadable")))).toBeTruthy();
  expect(within(screen.getByRole("row", { name: /Other share/ })).queryByRole("button")).toBeNull();
  await userEvent.click(row.getByRole("button", { name: t("file-audit.screen.check") }));
  await waitFor(() => expect(mocks.agentAction).toHaveBeenCalledExactlyOnceWith("file-audit", { ...target, expected_revision: 3 }));
  expect(await row.findByText(new RegExp(t("file-audit.screen.check_verified") + " · .*:03"))).toBeTruthy();
  expect(row.queryByText(new RegExp(t("file-audit.screen.audit_unreadable")))).toBeNull();
});

it.each([
  ["delete", "actions", "operation", "delete"],
  ["changes", "actions", "activity", "changes"],
  ["permission-changes", "permission-changes", "operation", null],
  ["access-denials", "access-denials", "operation", null],
  ["out-of-hours", "out-of-hours", "operation", null],
] as const)("opens the %s action filter in its assigned report", async (filter, target, parameter, value) => {
  mount();
  await userEvent.click(await screen.findByRole("button", { name: t('file-audit.filters.' + filter as 'file-audit.filters.all') }));
  await waitFor(() => expect(mocks.data.mock.calls.at(-1)?.[0]).toBe('file-audit.' + target));
  await waitFor(() => expect(mocks.data.mock.calls.at(-1)?.[1].get(parameter)).toBe(value));
  expect(screen.getByRole("tab", { name: t("file-audit.screen.actions") }).getAttribute("aria-selected")).toBe("true");
});

it("applies a custom period from the header and preserves an unchanged exact boundary", async () => {
  const from = "2026-10-23T11:59:37.125Z";
  const to = "2026-10-24T11:59:37.125Z";
  window.history.replaceState({}, "", `/app/report/file-audit.actions?${new URLSearchParams({ period: "custom", from, to })}`);
  mount();
  await screen.findByRole("table");
  await userEvent.click(screen.getByLabelText(new RegExp(t("period.custom")), { selector: "summary" }));
  expect((screen.getByLabelText(t("period.from")) as HTMLInputElement).value).toBe(from.slice(0, -1).replace("T", " "));
  fireEvent.change(screen.getByLabelText(t("period.to")), { target: { value: "2026-10-24 12:30" } });
  expect(mocks.data.mock.calls.at(-1)?.[1].get("to")).toBe(to);
  await userEvent.click(screen.getByRole("button", { name: t("filters.apply") }));
  await waitFor(() => expect(mocks.data.mock.calls.at(-1)?.[1].get("to")).toBe("2026-10-24T12:30:00.000Z"));
  expect(mocks.data.mock.calls.at(-1)?.[1].get("from")).toBe(from);
});

it("renders an aggregate, qualified account and Problem link, and expands inside the table", async () => {
  mocks.data.mockImplementation(async (key, params) => ({ ...result(key, params), items: [{
    id: "group", path: "C:\\Fixture\\<name>", operation: "permissions", source_name: "FS.example.test",
    subject_name: "EXAMPLE\\operator", subject_sid: "S-1-5-21-100000001-200000002-300000003-1199",
    aggregate: { first_seen_utc: "2026-11-24T08:12:01Z", last_seen_utc: "2026-11-24T08:12:30Z", count: 7 },
    problem_id: 12, evidence: [{ event_id: 4670, record_id: 41607 }],
  }] }));
  mount();
  const table = within(await screen.findByRole("table", { name: t("file-audit.screen.actions") }));
  expect(table.queryByRole("columnheader", { name: t("file-audit.screen.from") })).toBeNull();
  expect(table.getByText("×7")).toBeTruthy();
  expect(table.getByText("EXAMPLE\\operator")).toBeTruthy();
  expect(table.getByRole("link", { name: t("file-audit.screen.problem_number", { id: "12" }) }).getAttribute("href"))
    .toBe("/app/report/security.problems?id=12");
  const action = table.getByRole("button", { name: "C:\\Fixture\\<name>" });
  await userEvent.click(action);
  const sid = table.getByText("S-1-5-21-100000001-200000002-300000003-1199");
  expect(sid.closest("td")?.colSpan).toBeGreaterThan(1);
  expect(table.getByText("4670 · 41607")).toBeTruthy();
  expect(screen.queryByRole("dialog")).toBeNull();
  await userEvent.click(action);
  expect(table.queryByText("S-1-5-21-100000001-200000002-300000003-1199")).toBeNull();
});

it("sends typed searches to the server and resets the cursor when using 200 rows", async () => {
  mocks.data.mockImplementation(async (key, params) => ({ ...result(key, params), items: [{
    id: "client", path: "Synthetic object", client_ip: "192.0.2.1", subject_sid: "S-1-5-18",
  }] }));
  mount();
  const table = within(await screen.findByRole("table"));
  expect(table.getByRole("columnheader", { name: t("file-audit.screen.from") })).toBeTruthy();
  expect(table.getByText("192.0.2.1")).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: t("table.next") }));
  await waitFor(() => expect(mocks.data.mock.calls.at(-1)?.[1].get("cursor")).toBe("synthetic-cursor"));
  await userEvent.click(screen.getByRole("radio", { name: "200" }));
  await waitFor(() => expect(mocks.data.mock.calls.at(-1)?.[1].get("limit")).toBe("200"));
  expect(mocks.data.mock.calls.at(-1)?.[1].get("cursor")).toBeNull();
  fireEvent.change(await screen.findByRole("searchbox", { name: t("file-audit.screen.path_search") }), { target: { value: "filename.txt" } });
  await waitFor(() => expect(mocks.data.mock.calls.at(-1)?.[1].get("path_search")).toBe("filename.txt"));
  fireEvent.change(await screen.findByRole("searchbox", { name: t("file-audit.screen.account_search") }), { target: { value: "EXAMPLE\\operator" } });
  await waitFor(() => expect(mocks.data.mock.calls.at(-1)?.[1].get("account_search")).toBe("EXAMPLE\\operator"));
});

it("opens the exact server and resource from the permission-change count", async () => {
  window.history.replaceState({}, "", "/app/report/file-audit.overview");
  const entry = { id: "root", path: "C:\\Fixture", source_name: "FS.example.test", share_name: "Documents",
    agent_id: "fixture-agent", source_instance_id: "fixture-source", collection_scope_id: "fixture-root",
    permission_changes: 7, permission_change_groups: 1, audit_received_at: "2026-11-24T08:12:01Z" };
  mocks.data.mockImplementation(async (key, params) => ({ ...result(key, params), items: [entry] }));
  mount(declaration("file-audit.overview"));
  const row = (await screen.findByText("Documents")).closest("tr")!;
  const target = new URL(within(row).getByRole("link", { name: "7" }).getAttribute("href")!, window.location.origin);
  expect(target.pathname).toBe("/app/report/file-audit.permission-changes");
  expect(target.searchParams.get("share")).toBe(JSON.stringify(["fixture-agent", "fixture-source", "fixture-root"]));
  expect(target.searchParams.get("record_unit")).toBe("saved_event_group");
  expect(target.searchParams.get("from")).toBe(mocks.data.mock.calls.at(-1)?.[1].get("from"));
  expect(target.searchParams.get("to")).toBe(mocks.data.mock.calls.at(-1)?.[1].get("to"));
  expect(within(row).getByText("FS.example.test")).toBeTruthy();
});

it("hides stale rows and export on denial and names a failed result with retry", async () => {
  mocks.data.mockRejectedValueOnce(new ApiResponseError(403));
  mount();
  expect(await screen.findByText("Denied")).toBeTruthy();
  expect(screen.queryByRole("table")).toBeNull();
  expect(screen.queryByRole("link", { name: /CSV/ })).toBeNull();
  mocks.data.mockRejectedValueOnce(new ApiResponseError(500));
  await userEvent.click(screen.getByRole("tab", { name: t("file-audit.screen.overview") }));
  expect(await screen.findByText(t("file-audit.screen.load_error", { subject: t("file-audit.screen.overview") }))).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: t("state.retry") }));
  expect(await screen.findByRole("table")).toBeTruthy();
});

it("shows a next action for an empty successful result and keeps export independently authorized", async () => {
  mocks.access.capabilities = ["file-audit.view"];
  mocks.data.mockImplementation(async (key, params) => ({ ...result(key, params), items: [], has_more: false, filtered_count: 0 }));
  mount();
  const table = await screen.findByRole("table");
  expect(within(table).getByText(t("file-audit.screen.empty_actions"))).toBeTruthy();
  expect(screen.queryByRole("link", { name: /CSV/ })).toBeNull();
});
