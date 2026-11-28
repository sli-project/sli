// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ApiResponseError } from "../../api/client";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import { FileAuditReport } from "./FileAuditReport";
import { t } from "../../i18n";
import { OverlayProvider } from "../../design-system";
import { TimeZoneContext } from "../../shared/time-zone";
import reportDefinitions from "../../../../server-dotnet/src/Sli.Server/Reporting/V2/report-definitions.json";

const mocks = vi.hoisted(() => ({ definition: vi.fn(), data: vi.fn(), detail: vi.fn(), eventAvailable: vi.fn(), agents: vi.fn(), agentAction: vi.fn(), access: {
  platform_owner: false, preview: false,
  subject: { type: "user", id: 1, coarse_role: "viewer" }, evaluated_at_utc: "synthetic-evaluation", capabilities: ["file-audit.view", "file-audit.export"],
  reports: ["overview", "actions", "mass-operations", "permission-changes", "access-denials", "out-of-hours", "permissions", "audit-state"].map((key) => ({
    report_key: `file-audit.${key}`, allowed: true, allowed_actions: ["view", "export"], scopes: [] as Array<Record<string, unknown>>,
  })),
} }));
vi.mock("../../api/client", async (importOriginal) => ({ ...await importOriginal<typeof import("../../api/client")>(),
  api: { reportV2Definition: mocks.definition, reportV2Data: mocks.data, reportV2Detail: mocks.detail, agents: mocks.agents,
    agentAction: mocks.agentAction, eventAvailable: mocks.eventAvailable } }));
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
  return render(<QueryClientProvider client={client}>
    <TimeZoneContext.Provider value={{ timeZone: "UTC", setTimeZone: () => undefined }}>
      <OverlayProvider><FileAuditReport definition={initial}/></OverlayProvider>
    </TimeZoneContext.Provider>
  </QueryClientProvider>);
}
beforeEach(() => {
  localStorage.clear();
  window.history.replaceState({}, "", "/app/report/file-audit.actions");
  mocks.definition.mockReset().mockImplementation(async (key: string) => declaration(key));
  mocks.data.mockReset().mockImplementation(async (key: string, params: URLSearchParams) => result(key, params));
  mocks.detail.mockReset();
  mocks.eventAvailable.mockReset();
  mocks.access.capabilities = ["file-audit.view", "file-audit.export"];
  mocks.access.platform_owner = false;
  mocks.access.preview = false;
  mocks.access.subject.coarse_role = "viewer";
  mocks.access.reports.forEach(report => { report.scopes = []; });
  mocks.agents.mockReset().mockResolvedValue({ items: [] });
  mocks.agentAction.mockReset().mockResolvedValue({ command_id: "new-check", policy_revision: 4, state: "pending" });
});
afterEach(() => { cleanup(); client?.clear(); vi.useRealTimers(); });

it("keeps the donor tab order and the same period on direct Actions links and tab switches", async () => {
  mount();
  await screen.findByRole("table", { name: t("file-audit.screen.actions") });
  const actions = screen.getByRole("tab", { name: t("file-audit.screen.actions") });
  expect(actions.getAttribute("aria-selected")).toBe("true");
  expect(screen.getAllByRole("tab").map(tab => tab.textContent)).toEqual([
    t("file-audit.screen.overview"), t("file-audit.screen.actions"), t("file-audit.tabs.mass-operations"),
    t("file-audit.tabs.permission-changes"), t("file-audit.tabs.access-denials"), t("file-audit.tabs.out-of-hours"),
    t("file-audit.screen.permissions"), t("file-audit.tabs.audit-state"),
  ]);
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

it("shows nine resources on two servers and sends the deviations filter to the overview reader", async () => {
  const shares = ["Finance", "Projects", "Archive", "Public", "Design", "HR", "Reports", "QA", "Transfer"];
  const rows = shares.map((share_name, index) => ({
    id: share_name, share_name, source_name: index < 5 ? "fs-01.example.test" : "fs-02.example.test",
    source_instance_id: index < 5 ? "fixture-source-1" : "fixture-source-2",
    agent_id: index < 5 ? "fixture-agent-1" : "fixture-agent-2",
    collection_scope_id: "fixture-root-" + index, path: "C:\\Shares\\" + share_name,
    permission_changes: index === 0 ? 7 : 0, permission_change_groups: index === 0 ? 1 : 0,
    top_fact: index === 0 ? { kind: "mass", rule: "file-audit.mass-write", severity: "medium", paths: 110, id: "saved-result" }
      : index === 1 ? { kind: "audit_disabled" } : undefined,
  }));
  mocks.data.mockImplementation(async (key, params) => {
    const items = params.get("deviations_only") === "true" ? rows.filter(row => row.top_fact) : rows;
    return { ...result(key, params), items, filtered_count: items.length, has_more: false, next_cursor: null };
  });
  mount(declaration("file-audit.overview"));
  const table = within(await screen.findByRole("table", { name: t("file-audit.screen.overview") }));
  expect(table.getAllByRole("columnheader").map(cell => cell.textContent)).toEqual([
    t("file-audit.workspace.server"), t("file-audit.workspace.resource_path"), t("file-audit.overview.fact"),
    t("file-audit.workspace.permission_changes"), t("file-audit.overview.latest_change"), t("file-audit.overview.snapshot"),
  ]);
  expect(table.getAllByRole("row").slice(1)).toHaveLength(9);
  expect(table.getAllByText("fs-01.example.test")).toHaveLength(5);
  expect(table.getAllByText("fs-02.example.test")).toHaveLength(4);
  expect(table.getByText(new RegExp(t("file-audit.overview.mass_write", { count: 110 })))).toBeTruthy();
  expect(table.getByText(t("file-audit.overview.audit_disabled"))).toBeTruthy();
  expect(table.queryByRole("checkbox")).toBeNull();
  expect(screen.getByText(t("file-audit.overview.count_many", { count: 9 }))).toBeTruthy();
  await userEvent.click(screen.getByRole("checkbox", { name: t("file-audit.overview.deviations") }));
  await waitFor(() => expect(mocks.data.mock.calls.at(-1)?.[1].get("deviations_only")).toBe("true"));
  expect(await screen.findByText(t("file-audit.overview.count_few", { count: 2 }))).toBeTruthy();
  expect(screen.getAllByRole("row").slice(1)).toHaveLength(2);
  expect(screen.getByRole("link", { name: t("file-audit.overview.export") }).getAttribute("href")).toContain("deviations_only=true");
  expect(mocks.data.mock.calls.at(-1)?.[1].get("cursor")).toBeNull();
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

it("shows the server's agent upgrade requirement on Audit", async () => {
  mocks.data.mockImplementation(async (key, params) => ({ ...result(key, params), items: [{
    id: "fixture-resource", share_name: "Fixture share", audit_receipt: {
      observed_at: "2026-11-26T08:00:00Z", state: "failed", reason_code: "native_unavailable",
      check_agent_requirement: { agent_version: "26.0.136", minimum_version: "26.0.154" },
    },
  }] }));
  mount(declaration("file-audit.audit-state"));
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
  mount(declaration("file-audit.audit-state"));
  const row = await screen.findByRole("row", { name: /Fixture share/ });
  expect(row.textContent).toContain(t(message));
  expect(row.textContent).not.toContain(t("file-audit.screen.no_batch"));
});

it("shows all catalog shares and applies audit to the two confirmed selections", async () => {
  const shares = ["Finance", "Projects", "Archive", "Public", "NETLOGON", "SYSVOL"];
  const agent_id = "11111111-1111-4111-8111-111111111111";
  const source_instance_id = "synthetic-source";
  let verified = false;
  let receivedBatch = false;
  mocks.data.mockImplementation(async (key, params) => ({ ...result(key, params),
    filtered_count: shares.length, has_more: false, next_cursor: null,
    items: shares.map((share_name, index) => ({
      id: share_name, share_name, source_name: "fs.example.test", path: `C:\\Shares\\${share_name}`,
      agent_id, source_instance_id, collection_scope_id: `scope:${index}`, audit_revision: 3,
      audit_state: index === 0 || verified && index <= 2 ? "enabled" : "disabled",
      audit_checked_at: index === 0 || verified && index <= 2 ? "2026-11-26T08:00:00Z" : null,
      audit_policy_revision: verified ? 4 : 3,
      audit_received_at: receivedBatch && index === 1 ? "2026-11-26T08:15:00Z" : null,
    })),
  }));
  mocks.agentAction.mockResolvedValue({ command_id: "apply-shares", policy_revision: 4, state: "pending" });
  mount(declaration("file-audit.audit-state"));
  const table = within(await screen.findByRole("table", { name: t("file-audit.tabs.audit-state") }));
  expect(table.getAllByRole("row").slice(1)).toHaveLength(6);
  expect(table.getByRole("row", { name: /Finance/ }).textContent).toContain(t("file-audit.resources.enabled"));
  expect(table.getByRole("row", { name: /Projects/ }).textContent).toContain(t("file-audit.resources.disabled"));
  for (const key of ["condition", "observed", "checked"] as const)
    expect(table.getByRole("columnheader", { name: t(`file-audit.audit.${key}`) })).toBeTruthy();
  for (const share of ["Projects", "Archive"]) await userEvent.click(within(table.getByRole("row", { name: new RegExp(share) })).getByRole("checkbox"));
  expect(table.getByRole("checkbox", { name: t("file-audit.resources.selectPage") })).toHaveProperty("indeterminate", true);
  await userEvent.click(screen.getByRole("button", { name: t("file-audit.resources.enable") }));
  const dialog = within(await screen.findByRole("dialog", { name: t("file-audit.resources.enable") }));
  expect(dialog.getByText("fs.example.test · Projects")).toBeTruthy();
  expect(dialog.getByText("fs.example.test · Archive")).toBeTruthy();
  await userEvent.click(dialog.getByRole("button", { name: t("file-audit.resources.confirmEnable") }));
  await waitFor(() => expect(mocks.agentAction).toHaveBeenCalledExactlyOnceWith("file-audit", {
    agent_id, source_instance_id, expected_revision: 3, action: "apply", collection_scope_ids: ["scope:1", "scope:2"],
  }));
  expect(await table.findAllByText(t("file-audit.resources.applying"))).toHaveLength(2);
  verified = true;
  await act(() => client.invalidateQueries({ queryKey: ["report-v2", "file-audit"] }));
  const projects = within(table.getByRole("row", { name: /Projects/ }));
  expect(await projects.findByText(t("file-audit.screen.no_batch"))).toBeTruthy();
  expect(projects.getByText(new RegExp(t("file-audit.resources.enabled")))).toBeTruthy();
  receivedBatch = true;
  await act(() => client.invalidateQueries({ queryKey: ["report-v2", "file-audit"] }));
  expect(await projects.findByText(new RegExp(t("file-audit.screen.last_batch", { time: ".*08:15" })))).toBeTruthy();
  expect(projects.queryByText(t("file-audit.screen.no_batch"))).toBeNull();
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
  mount(declaration("file-audit.audit-state"));
  const row = within(await screen.findByRole("row", { name: /Fixture share/ }));
  expect(row.getByText(new RegExp(t("file-audit.screen.audit_unreadable")))).toBeTruthy();
  expect(within(screen.getByRole("row", { name: /Other share/ })).queryByRole("button")).toBeNull();
  await userEvent.click(row.getByRole("button", { name: t("file-audit.screen.check") }));
  await waitFor(() => expect(mocks.agentAction).toHaveBeenCalledExactlyOnceWith("file-audit", { ...target, expected_revision: 3 }));
  expect(await row.findByText(t("file-audit.screen.check_verified"))).toBeTruthy();
  expect(row.getByText(/08:03/)).toBeTruthy();
  expect(row.queryByText(new RegExp(t("file-audit.screen.audit_unreadable")))).toBeNull();
});

it.each([
  ["delete", "actions", "operation", "delete"],
  ["changes", "actions", "activity", "changes"],
  ["permission-changes", "permission-changes", "operation", null],
  ["access-denials", "access-denials", "operation", null],
  ["out-of-hours", "out-of-hours", "operation", null],
] as const)("preserves the scope of a bookmarked %s filter", async (filter, target, parameter, value) => {
  window.history.replaceState({}, "", "/app/report/file-audit.actions?action_filter=" + filter);
  mount();
  await waitFor(() => expect(mocks.data.mock.calls.at(-1)?.[0]).toBe('file-audit.' + target));
  await waitFor(() => expect(mocks.data.mock.calls.at(-1)?.[1].get(parameter)).toBe(value));
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

it("expands a grouped interval across the table and links only to available targets", async () => {
  const path = "C:\\Fixture\\<name>";
  mocks.eventAvailable.mockResolvedValue(true);
  mocks.data.mockImplementation(async (key, params) => ({ ...result(key, params), items: [{
    id: "group", path, operation: "permissions", source_name: "FS.example.test", event_code: 4670, journal: "Security",
    subject_name: "EXAMPLE\\operator", subject_sid: "S-1-5-21-100000001-200000002-300000003-1199",
    aggregate: { first_seen_utc: "2026-11-24T08:12:01Z", last_seen_utc: "2026-11-24T08:12:30Z", count: 7, boundary: "overlap" },
    problem_id: 12, evidence: [{ event_id: 4670, record_id: 41607, role: "primary", reference: "event_cold_facts:44" }],
  }] }));
  mount();
  const table = within(await screen.findByRole("table", { name: t("file-audit.screen.actions") }));
  expect(table.queryByRole("columnheader", { name: t("file-audit.activity.client") })).toBeNull();
  expect(table.getByText(t("file-audit.activity.in_group", { count: "7" }))).toBeTruthy();
  expect(table.getByText("EXAMPLE\\operator")).toBeTruthy();
  expect(table.getByText(path)).toBeTruthy();
  const group = table.getByText(path).closest("tr")!;
  expect(group.hasAttribute("data-clickable")).toBe(true);
  await userEvent.click(group);
  expect(table.getByRole("link", { name: t("file-audit.screen.problem_number", { id: "12" }) }).getAttribute("href"))
    .toBe("/app/report/security.problems?id=12");
  const sid = table.getByText(/S-1-5-21-100000001-200000002-300000003-1199/);
  expect(sid.closest("td")?.colSpan).toBe(6);
  expect(table.getByText("4670 · 41607")).toBeTruthy();
  expect((await table.findByRole("link", { name: t("file-audit.activity.saved_record") })).getAttribute("href")).toBe("/app/events/44");
  expect(table.queryByRole("link", { name: t("file-audit.activity.object_permissions") })).toBeNull();
  expect(table.queryByRole("link", { name: t("file-audit.activity.compare") })).toBeNull();
  expect(screen.queryByRole("dialog")).toBeNull();
  await userEvent.click(table.getByRole("button", { name: t("file-audit.activity.collapse") }));
  expect(table.queryByText(/S-1-5-21-100000001-200000002-300000003-1199/)).toBeNull();
});

it("opens a stored mass-operation window with its own condition, counts and published problem", async () => {
  mocks.data.mockImplementation(async (key, params) => ({ ...result(key, params), items: key === "file-audit.mass-operations" ? [{
    id: "episode", operation: "write", source_name: "FS.example.test", share_name: "Finance", subject_name: "EXAMPLE\\operator",
    details: { window_start: "2026-11-24T08:12:01Z", window_end: "2026-11-24T08:17:01Z", distinct_files: 110,
      threshold: 100, window_seconds: 300 }, observation_count: 125, problem_id: 12,
    evidence: [{ path: "C:\\Finance\\report.csv" }],
  }] : [] }));
  mount();
  await userEvent.click(screen.getByRole("tab", { name: t("file-audit.tabs.mass-operations") }));
  const table = within(await screen.findByRole("table", { name: t("file-audit.tabs.mass-operations") }));
  expect(table.getByText("110")).toBeTruthy();
  expect(table.getByText("125")).toBeTruthy();
  expect(table.getByText(t("file-audit.activity.condition_value", { count: "100", seconds: "300" }))).toBeTruthy();
  expect(table.getByRole("link", { name: t("file-audit.screen.problem_number", { id: "12" }) }).getAttribute("href"))
    .toBe("/app/report/security.problems?id=12");
  await userEvent.click(table.getByRole("button", { name: t("file-audit.activity.expand") }));
  expect(table.getByText("C:\\Finance\\report.csv")).toBeTruthy();
});

it("shows the missing schedule without a measured count or download", async () => {
  mocks.data.mockImplementation(async (key, params) => ({ ...result(key, params), state: "partial",
    items: [], filtered_count: 0, coverage: { reason: "schedule_not_configured" } }));
  mount(declaration("file-audit.out-of-hours"));
  expect(await screen.findByText(t("file-audit.activity.no_schedule"))).toBeTruthy();
  expect(screen.queryByText(t("file-audit.activity.no_records"))).toBeNull();
  expect(screen.queryByRole("link", { name: t("reports.renderer.export_csv") })).toBeNull();
});

it("sends typed searches to the server and resets the cursor when using 200 rows", async () => {
  mocks.data.mockImplementation(async (key, params) => ({ ...result(key, params), items: [{
    id: "client", path: "Synthetic object", client_ip: "192.0.2.1", subject_sid: "S-1-5-18",
  }] }));
  mount();
  const table = within(await screen.findByRole("table"));
  expect(table.queryByText("192.0.2.1")).toBeNull();
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
