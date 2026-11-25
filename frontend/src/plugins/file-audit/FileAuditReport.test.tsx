// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ApiResponseError } from "../../api/client";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import { FILE_AUDIT_TABS, tabTitle } from "./report";
import { FileAuditReport } from "./FileAuditReport";
import { t, setLocale, localeRuntime } from "../../i18n";
import reportDefinitions from "../../../../server-dotnet/src/Sli.Server/Reporting/V2/report-definitions.json";
import type { FileAuditDetailResult } from "./acl";

const mocks = vi.hoisted(() => ({ definition: vi.fn(), data: vi.fn(), detail: vi.fn(), agents: vi.fn(), access: {
  platform_owner: false, preview: false,
  subject: { type: "user", id: 1, coarse_role: "viewer" }, evaluated_at_utc: "synthetic-evaluation", capabilities: ["file-audit.view", "file-audit.export"],
  reports: ["overview", "actions", "mass-operations", "permission-changes", "access-denials", "out-of-hours", "permissions", "audit-state"].map((key) => ({
    report_key: `file-audit.${key}`, allowed: true, allowed_actions: ["view", "export"], scopes: [] as Array<Record<string, unknown>>,
  })),
} }));
vi.mock("../../api/client", async (importOriginal) => ({ ...await importOriginal<typeof import("../../api/client")>(),
  api: { reportV2Definition: mocks.definition, reportV2Data: mocks.data, reportV2Detail: mocks.detail, agents: mocks.agents } }));
vi.mock("../../app/App", () => ({ useEffectiveAccess: () => mocks.access, useTimeZone: () => ({ timeZone: "UTC" }) }));
vi.mock("../../app/report-v2/ReportDenied", () => ({ ReportDenied: () => <div role="alert">Denied</div> }));

const declaration = (key = "file-audit.actions"): ReportDefinitionDto => ({
  key, section: "reports/file-audit", title: "Fixture report", description: "", archetype: "list",
  params: [
    { key: "period", label: "Period", kind: "period", required: true, default: "24h" },
    { key: "source_kind", label: "Source", kind: "choice", options: [{ value: "server", label: "Servers" }, { value: "workstation", label: "Workstations" }] },
    { key: "path", label: "Object", kind: "text" },
    { key: "include_nested", label: "Nested", kind: "choice" },
    { key: "employee", label: "Employee", kind: "text" },
    { key: "share", label: "Share", kind: "multichoice", options_from: "share" },
    { key: "operation", label: "Operation", kind: "choice", options: [{ value: "delete", label: "Удаление" }] },
  ], columns: [{ key: "path", path: "path", label: "Object", kind: "text" }],
  views: [{ key: "table", kind: "table", source: "items" }], row_key: "id", detail: "fields", export: true,
  limits: { default: 50, max: 100 }, presets: [], row_links: [], filter_options: {},
});
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
});
afterEach(() => { cleanup(); client?.clear(); vi.useRealTimers(); });

it("applies the source filter to data, URL, tabs and export and resets cursor", async () => {
  mount();
  await screen.findByText("1–50 из 52");
  fireEvent.change(screen.getByLabelText(t("file-audit.source")), { target: { value: "workstation" } });
  await userEvent.click(screen.getByRole("button", { name: "Применить" }));
  await waitFor(() => expect(mocks.data.mock.calls.at(-1)?.[1].get("source_kind")).toBe("workstation"));
  expect(new URLSearchParams(window.location.search).get("source_kind")).toBe("workstation");
  expect(screen.getByRole("link", { name: /CSV/ }).getAttribute("href")).toContain("source_kind=workstation");
  await userEvent.click(screen.getByRole("tab", { name: "Отказы доступа" }));
  await waitFor(() => expect(mocks.data.mock.calls.at(-1)?.[0]).toBe("file-audit.access-denials"));
  expect(mocks.data.mock.calls.at(-1)?.[1].get("source_kind")).toBe("workstation");
  expect(mocks.data.mock.calls.at(-1)?.[1].get("cursor")).toBeNull();
});

it("uses the applied server share and subtree from the permission report link", async () => {
  const key = "file-audit.permission-changes";
  const share = JSON.stringify(["synthetic-agent", "bound-source", "pilot-scope"]);
  const path = "C:\\Pilot";
  const params = new URLSearchParams({
    period: "24h", source_kind: "server", path, share, operation: "permissions", include_nested: "true",
  });
  window.history.replaceState({}, "", `/app/report/${key}?${params}`);
  mount(declaration(key));
  await screen.findByRole("table", { name: tabTitle("permission-changes") });
  expect(mocks.data.mock.calls.at(-1)?.[0]).toBe(key);
  const actual = mocks.data.mock.calls.at(-1)?.[1] as URLSearchParams;
  expect(actual.getAll("share")).toEqual([share]);
  for (const filter of ["source_kind", "path", "operation", "include_nested"]) {
    expect(actual.get(filter)).toBe(params.get(filter));
  }
  expect(actual.get("period")).toBe("custom");
  expect(Date.parse(actual.get("to")!) - Date.parse(actual.get("from")!)).toBe(24 * 60 * 60 * 1000);
});

it.each(FILE_AUDIT_TABS)("opens %s through its authorized v2 report key", async (tab) => {
  mount();
  expect(screen.getAllByRole("tab")).toHaveLength(8);
  await userEvent.click(screen.getByRole("tab", { name: tabTitle(tab) }));
  await waitFor(() => expect(mocks.data).toHaveBeenCalledWith(`file-audit.${tab}`, expect.any(URLSearchParams)));
  await screen.findByRole("table", { name: tabTitle(tab) });
  expect(screen.getByRole("tab", { name: tabTitle(tab) }).getAttribute("aria-selected")).toBe("true");
  expect(window.location.pathname).toBe(`/app/report/file-audit.${tab}`);
  expect(new URLSearchParams(window.location.search).get("tab")).toBe(tab);
});

it.each(FILE_AUDIT_TABS)("keeps one complete filter panel on %s and applies a custom date-time range", async (tab) => {
  mount();
  await userEvent.click(screen.getByRole("tab", { name: tabTitle(tab) }));
  await screen.findByRole("table", { name: tabTitle(tab) });
  const form = screen.getByRole("form", { name: "Фильтры" });
  expect(screen.getAllByRole("form", { name: "Фильтры" })).toHaveLength(1);
  expect(within(form).getAllByRole("radio").map((radio) => radio.textContent)).toEqual(["24 часа", "7 дней", "30 дней", "Свой период"]);
  expect(within(form).getAllByRole("combobox", { name: t("file-audit.share") })).toHaveLength(1);
  expect(within(form).getByLabelText(t("file-audit.employee"))).toBeTruthy();
  expect(within(form).getByLabelText("Действие")).toBeTruthy();
  expect(within(form).getByLabelText("Включая вложенные")).toBeTruthy();
  await userEvent.click(screen.getByRole("radio", { name: "Свой период" }));
  const from = screen.getByLabelText("С"), to = screen.getByLabelText("По");
  expect(from.getAttribute("type")).toBe("datetime-local");
  expect(to.getAttribute("type")).toBe("datetime-local");
  fireEvent.change(from, { target: { value: "2026-10-01T09:15" } });
  fireEvent.change(to, { target: { value: "2026-10-01T10:45" } });
  await userEvent.click(screen.getByRole("button", { name: "Применить" }));
  await waitFor(() => expect(mocks.data.mock.calls.at(-1)?.[1].get("from")).toBe("2026-10-01T09:15:00.000Z"));
  expect(mocks.data.mock.calls.at(-1)?.[1].get("to")).toBe("2026-10-01T10:45:00.000Z");
});

it("places group assignments after permission findings", async () => {
  mocks.definition.mockImplementation(async (key: string) => ({ ...declaration(key), views: [
    { key: "table", kind: "table", source: "items" },
    { key: "groups", kind: "table", source: "groups", title: "Synthetic group assignments", columns: [
      { key: "subject_sid", path: "subject_sid", label: "Group", kind: "text" },
    ] },
  ] }));
  mocks.data.mockImplementation(async (key: string, params: URLSearchParams) => ({ ...result(key, params),
    collections: { groups: [{ subject_sid: "synthetic-group" }] },
  }));
  mount();
  await userEvent.click(screen.getByRole("tab", { name: "Права доступа" }));
  const findings = await screen.findByRole("table", { name: "Права доступа" });
  const groups = await screen.findByRole("table", { name: "Synthetic group assignments" });
  expect(findings.compareDocumentPosition(groups) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
});

it("shows settings evidence without claiming every operation was delivered", async () => {
  mocks.data.mockImplementation(async (key: string, params: URLSearchParams) => ({ ...result(key, params),
    items: [{ id: "audit", path: "Synthetic audited root", audit_receipt: {
      required_masks: { "synthetic-guid": 3 }, actual_masks: { "synthetic-guid": 1 },
    } }], has_more: false, next_cursor: null, filtered_count: 1,
  }));
  mount();
  await userEvent.click(screen.getByRole("tab", { name: tabTitle("audit-state") }));
  expect(await screen.findByText(t("file-audit.audit_scope_note"))).toBeTruthy();
  await userEvent.click(screen.getByText("Synthetic audited root"));
  expect(await screen.findByText(t("file-audit.receipt.required_masks"))).toBeTruthy();
  expect(screen.getByText('{"synthetic-guid":3}')).toBeTruthy();
  expect(screen.getByText('{"synthetic-guid":1}')).toBeTruthy();
});

it("keeps the shared filters across tabs and resets pagination on Apply", async () => {
  mount();
  await screen.findByText("1–50 из 52");
  fireEvent.change(screen.getByLabelText("Объект"), { target: { value: "C:\\Synthetic\\Folder" } });
  await userEvent.click(screen.getByLabelText("Включая вложенные"));
  fireEvent.change(screen.getByLabelText(t("file-audit.employee")), { target: { value: "synthetic-user" } });
  fireEvent.change(screen.getByLabelText("Действие"), { target: { value: "delete" } });
  await userEvent.click(screen.getByRole("button", { name: "Применить" }));
  await waitFor(() => expect(mocks.data.mock.calls.at(-1)?.[1].get("path")).toBe("C:\\Synthetic\\Folder"));
  await userEvent.click(screen.getByRole("tab", { name: "Отказы доступа" }));
  await waitFor(() => expect(mocks.data.mock.calls.at(-1)?.[0]).toBe("file-audit.access-denials"));
  const sent = mocks.data.mock.calls.at(-1)![1] as URLSearchParams;
  expect(sent.get("employee")).toBe("synthetic-user");
  expect(sent.get("include_nested")).toBe("false");
  expect(sent.get("operation")).toBe("delete");
  expect(sent.get("cursor")).toBeNull();
});

it("uses cursor pages in both directions and exports the current filters without the page limit", async () => {
  mount();
  await screen.findByText("1–50 из 52");
  expect((screen.getByRole("button", { name: "Назад" }) as HTMLButtonElement).disabled).toBe(true);
  await userEvent.click(screen.getByRole("button", { name: "Вперёд" }));
  await screen.findByText("51–52 из 52");
  expect(screen.queryByText("Synthetic object 0")).toBeNull();
  expect((screen.getByRole("button", { name: "Вперёд" }) as HTMLButtonElement).disabled).toBe(true);
  await userEvent.click(screen.getByRole("button", { name: "Назад" }));
  await screen.findByText("1–50 из 52");
  const href = screen.getByRole("link", { name: /CSV/ }).getAttribute("href")!;
  expect(href).toContain("/file-audit.actions/export.csv?");
  expect(href).not.toContain("limit=");
  expect(href).not.toContain("cursor=");
});

it("applies page size to the server request and resets a previous cursor", async () => {
  mocks.definition.mockImplementation(async (key: string) => ({ ...declaration(key), limits: { default: 50, max: 200 } }));
  mocks.data.mockImplementation(async (key: string, params: URLSearchParams) => ({ ...result(key, params),
    items: Array.from({ length: Number(params.get("limit")) }, (_, index) => ({ id: String(index), path: `Paged object ${index}` })),
    filtered_count: 260,
  }));
  mount({ ...declaration(), limits: { default: 50, max: 200 } });
  await screen.findByText("1–50 из 260");
  await userEvent.click(screen.getByRole("button", { name: "Вперёд" }));
  await screen.findByText("51–100 из 260");
  fireEvent.change(screen.getByLabelText(t("table.rowsPerPage")), { target: { value: "200" } });
  await screen.findByText("1–200 из 260");
  expect(mocks.data.mock.calls.at(-1)?.[1].get("limit")).toBe("200");
  expect(mocks.data.mock.calls.at(-1)?.[1].get("cursor")).toBeNull();
  expect(new URLSearchParams(window.location.search).get("limit")).toBe("200");
});

it("opens retained row details across the full page and restores its cursor on return", async () => {
  mount();
  await screen.findByText("1–50 из 52");
  await userEvent.click(screen.getByRole("button", { name: "Вперёд" }));
  await userEvent.click(await screen.findByText("Synthetic object 50"));
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(screen.getByRole("region", { name: t("file-audit.workspace.evidence") })).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: t("file-audit.workspace.back") }));
  await screen.findByText("51–52 из 52");
  expect(mocks.data.mock.calls.at(-1)?.[1].get("cursor")).toBe("synthetic-cursor");
});

it("hides prior rows, full-page details and export when a tab denies access", async () => {
  mount();
  await userEvent.click(await screen.findByText("Synthetic object 0"));
  expect(screen.getByRole("region", { name: t("file-audit.workspace.evidence") })).toBeTruthy();
  mocks.data.mockRejectedValueOnce(new ApiResponseError(403, "report_access_denied"));
  await userEvent.click(screen.getByRole("tab", { name: "Права доступа" }));
  expect(await screen.findByText("Denied")).toBeTruthy();
  expect(screen.queryByRole("table")).toBeNull();
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(screen.queryByRole("link", { name: /CSV/ })).toBeNull();
  expect(screen.getAllByRole("tab")).toHaveLength(8);
});

it("shows partial results and unknown totals without a warning banner or a complete empty result", async () => {
  mocks.data.mockImplementation(async (key: string, params: URLSearchParams) => ({ ...result(key, params),
    state: "partial", items: [], filtered_count: null, has_more: false, next_cursor: null,
    metrics: [{ key: "read", label: "Synthetic metric", value: null, quality: "unknown" }],
  }));
  const { container } = mount();
  await screen.findByText("0–0 из —");
  expect(screen.queryByRole("status")).toBeNull();
  expect(container.querySelector(".sli-ds-state--banner")).toBeNull();
  expect(screen.getByRole("table", { name: tabTitle("actions") })).toBeTruthy();
  expect(screen.queryByText(t("state.empty.title"))).toBeNull();
  expect(screen.queryByText("Synthetic metric")).toBeNull();
  expect(screen.queryByText("0–0 из 0")).toBeNull();
});

it("keeps export hidden without its independent capability", async () => {
  mocks.access.capabilities = ["file-audit.view"];
  mount();
  await screen.findByText("1–50 из 52");
  expect(screen.queryByRole("link", { name: /CSV/ })).toBeNull();
});

it("opens ACL from the overview with declared API parameters and a useful object index", async () => {
  const actualDefinition = (key: string) => ({ ...declaration(key),
    ...reportDefinitions.find(item => item.key === key), filter_options: {},
  }) as ReportDefinitionDto;
  const permissions = actualDefinition("file-audit.permissions");
  const snapshot = "00000000-0000-4000-8000-000000000001";
  const previousSnapshot = "00000000-0000-4000-8000-000000000004";
  const root = { id: "fixture-root", agent_id: "00000000-0000-4000-8000-000000000002",
    source_instance_id: "fixture-source", collection_scope_id: "fixture-scope", source_name: "FS-01",
    share_name: "Reports", path: "D:\\Synthetic\\Reports", snapshot_id: snapshot, observed_at: "2026-11-25T08:00:00Z",
    permission_changes: 7, object_type: "directory", owner_sid: "S-1-5-18", completeness: "complete", record_unit: "observed_object" };
  const share = JSON.stringify([root.agent_id, root.source_instance_id, root.collection_scope_id]);
  const scope = new URLSearchParams({ tab: "overview", domain: "7", period: "custom", from: "2026-11-24T08:00:37.125Z",
    to: "2026-11-25T08:00:37.125Z", source_kind: "server", source_instance_id: root.source_instance_id,
    device_id: "00000000-0000-4000-8000-000000000003", path: root.path, include_nested: "true", share, limit: "200" });
  window.history.replaceState({}, "", `/app/report/file-audit.overview?${scope}`);
  mocks.definition.mockImplementation(async (key: string) => actualDefinition(key));
  mocks.data.mockImplementation(async (key: string, params: URLSearchParams) => ({ ...result(key, params),
    items: [root], filtered_count: 1, has_more: false, next_cursor: null }));
  mocks.detail.mockImplementation(async (key: string, id: string, params: URLSearchParams): Promise<FileAuditDetailResult> => {
    const allowed = new Set([...permissions.params.map(param => param.key), "from", "to", "cursor", "limit", "sort", "direction", "tz", "tab"]);
    const unknown = [...params.keys()].find(param => !allowed.has(param));
    if (unknown) throw new ApiResponseError(400, `report_parameter_unknown:${unknown}`);
    if (params.has("tab") && !permissions.views.some(view => view.key === params.get("tab"))) throw new ApiResponseError(400, "report_tab_invalid");
    const acl = { state: "complete" as const, raw: "D:", aces: [] };
    return { ...result(key, params), items: [], has_more: false, next_cursor: null, filtered_count: 0,
      detail: { snapshot: { id, observed_at: root.observed_at, policy_revision: "4", scan_id: "fixture-scan", page_number: 0,
        has_more: false, completeness: "complete", unread_objects: 0 },
        share: { name: root.share_name, path: root.path, complete: true, dacl: acl },
        object: { ...root, file_id: "fixture-file", dacl: acl, sacl: acl, sacl_protected: false },
        comparison: { state: params.has("compare_snapshot_id") ? "unavailable" : "not_requested",
          reason: params.has("compare_snapshot_id") ? "policy_incompatible" : null, identity_basis: null } },
      collections: { snapshots: [{ id: snapshot, observed_at: root.observed_at },
        { id: previousSnapshot, observed_at: "2026-11-24T08:00:00Z" }] } };
  });
  mount(actualDefinition("file-audit.overview"));
  await userEvent.click(await screen.findByRole("button", { name: root.share_name }));
  await screen.findByRole("table", { name: t("file-audit.acl.ntfs") });
  const [key, id, params] = mocks.detail.mock.calls.at(-1)! as [string, string, URLSearchParams];
  expect(key).toBe("file-audit.permissions"); expect(id).toBe(snapshot);
  for (const name of ["from", "to", "source_kind", "source_instance_id", "device_id", "path", "share", "limit"]) {
    expect(params.getAll(name), name).toEqual(scope.getAll(name));
  }
  expect(params.get("include_nested")).toBe("false");
  expect(new URLSearchParams(window.location.search).get("domain")).toBe("7");
  await userEvent.click(screen.getByRole("button", { name: t("file-audit.compare.title") }));
  await screen.findByText(t("file-audit.compare.reason.policy_incompatible"));
  const comparisonParams = mocks.detail.mock.calls.at(-1)![2] as URLSearchParams;
  expect(comparisonParams.get("compare_snapshot_id")).toBe(previousSnapshot);
  for (const [name, value] of params) expect(comparisonParams.get(name), name).toBe(value);
  expect(comparisonParams.has("domain")).toBe(false);
  await userEvent.click(screen.getByRole("link", { name: t("file-audit.workspace.back") }));
  await screen.findByRole("table", { name: tabTitle("overview") });
  const returned = new URLSearchParams(window.location.search);
  for (const [name, value] of scope) expect(returned.get(name), name).toBe(value);
  expect(returned.has("object_path")).toBe(false);
  await userEvent.click(screen.getByRole("tab", { name: tabTitle("permissions") }));
  const table = await screen.findByRole("table", { name: tabTitle("permissions") });
  expect(mocks.data.mock.calls.at(-1)![1].get("view")).toBe("objects");
  const useful = ["path", "source_name", "share_name", "object_type", "owner_sid", "observed_at", "completeness"];
  expect(within(table).getAllByRole("columnheader").map(header => header.textContent)).toEqual(
    permissions.columns.filter(column => useful.includes(column.key)).map(column => column.label));
  await userEvent.click(screen.getByText(t("table.columns")));
  const columnControls = screen.getByRole("group", { name: t("table.columns") });
  const snapshotColumn = permissions.columns.find(column => column.key === "snapshot_id")!;
  await userEvent.click(within(columnControls).getByRole("checkbox", { name: snapshotColumn.label }));
  expect(within(table).getByRole("cell", { name: snapshot })).toBeTruthy();
  for (const name of ["employee", "rule_code", "share_mask", "ntfs_mask"]) {
    const label = permissions.columns.find(column => column.key === name)!.label;
    expect((within(columnControls).getByRole("checkbox", { name: label }) as HTMLInputElement).checked).toBe(false);
  }
  await userEvent.click(within(table).getByRole("button", { name: root.path }));
  await screen.findByRole("table", { name: t("file-audit.acl.ntfs") });
});

it.each(["inside", "overlap"] as const)("keeps the resource counter's exact scope and window through %s evidence and return", async (groupBoundary) => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2026-10-24T12:00:00.000Z"));
  const share = JSON.stringify(["fixture-agent", "fixture-source", "fixture-root"]);
  const scope = new URLSearchParams({ tab: "overview", period: "24h", source_kind: "server", domain: "7", fa_anchor: "2026-10-24T11:59:37.125Z",
    path: "C:\\Synthetic\\Folder\\Nested", include_nested: "true", employee: "S-1-5-21-1-42", share });
  window.history.replaceState({}, "", `/app/report/file-audit.overview?${scope}`);
  const metadataColumns: ReportDefinitionDto["columns"] = [
    { key: "first_seen_utc", path: "first_seen_utc", label: "First seen", kind: "datetime" },
    { key: "last_seen_utc", path: "last_seen_utc", label: "Last seen", kind: "datetime" },
    { key: "aggregate_boundary", path: "aggregate.boundary", label: "Boundary", kind: "text" },
    { key: "aggregate_count_min", path: "aggregate.count_min", label: "Minimum", kind: "number" },
    { key: "aggregate_count_max", path: "aggregate.count_max", label: "Maximum", kind: "number" },
    { key: "correlation_state", path: "correlation_state", label: "Correlation", kind: "text" },
    { key: "record_unit", path: "record_unit", label: "Record unit", kind: "text" },
  ];
  const definitionFor = (key: string): ReportDefinitionDto => ({ ...declaration(key),
    params: [...declaration(key).params, { key: "record_unit", label: "Unit", kind: "choice" }],
    columns: key.endsWith("overview") ? [...declaration(key).columns,
      { key: "permission_changes", path: "permission_changes", label: "4670", kind: "number" }] : [...declaration(key).columns,
      { key: "observed_at", path: "observed_at", label: "Observed at", kind: "datetime" },
      { key: "count", path: "count", label: "Events in retained group", kind: "number" }, ...metadataColumns],
    detail: { kind: "inline", title: "Synthetic retained evidence", key: "id", inline: "evidence", row_links: [], columns: [
      { key: "reference", path: "reference", label: "Reference", kind: "code" },
      { key: "record_id", path: "record_id", label: "Record", kind: "number" },
    ] },
  });
  mocks.definition.mockImplementation(async (key: string) => definitionFor(key));
  const boundary = "2026-10-23T11:59:40.000Z";
  const firstSeen = groupBoundary === "overlap" ? "2026-10-23T11:59:30.000Z" : boundary;
  const countLabel = groupBoundary === "overlap" ? t("file-audit.workspace.group_count", { count: 7 }) : "7";
  mocks.data.mockImplementation(async (key: string, params: URLSearchParams): Promise<ReportResultDto> => {
    const response = result(key, params);
    if (key === "file-audit.overview") return { ...response, items: [{ id: "root", path: "C:\\Synthetic\\Folder",
      agent_id: "fixture-agent", source_instance_id: "fixture-source", collection_scope_id: "fixture-root", permission_changes: 7 }] };
    const included = params.get("record_unit") === "saved_event_group" && params.get("from")! <= boundary && boundary < params.get("to")!;
    return { ...response, items: included ? [{ id: "boundary-group", path: "Synthetic boundary group",
      record_unit: "saved_event_group", count: 7, first_seen_utc: firstSeen, last_seen_utc: "2026-10-23T11:59:41.000Z",
      correlation_state: "not_attempted",
      aggregate: { count: 7, first_seen_utc: firstSeen, last_seen_utc: "2026-10-23T11:59:41.000Z", boundary: groupBoundary,
        count_min: groupBoundary === "overlap" ? 1 : 7, count_max: groupBoundary === "overlap" ? 6 : 7, unit: "saved_event_group" },
      evidence: [{ reference: "retained-group-reference", record_id: 42 }] }] : [],
      filtered_count: included ? 1 : 0, has_more: false, next_cursor: null };
  });
  const first = mount(definitionFor("file-audit.overview"));
  const link = await screen.findByRole("link", { name: "7" });
  const overview = new URLSearchParams(mocks.data.mock.calls.at(-1)![1]);
  const href = link.getAttribute("href")!;
  const target = new URL(href, window.location.origin).searchParams;
  for (const key of ["from", "to", "source_kind", "path", "include_nested", "employee", "share", "tz"]) expect(target.getAll(key), key).toEqual(overview.getAll(key));
  expect(target.get("record_unit")).toBe("saved_event_group");
  expect(target.get("operation")).toBe("permissions");
  expect(target.get("domain")).toBe("7");
  expect(target.get("cursor")).toBeNull();
  vi.setSystemTime(new Date("2026-10-24T12:05:00.000Z"));
  first.unmount(); client.clear(); window.history.replaceState({}, "", href);
  mount(definitionFor("file-audit.permission-changes"));
  const table = await screen.findByRole("table", { name: tabTitle("permission-changes") });
  expect(within(table).getAllByRole("columnheader").map(header => header.textContent)).toEqual([
    "Object", t("file-audit.workspace.interval"), t("file-audit.workspace.count"),
  ]);
  expect(within(table).getByRole("cell", { name: countLabel })).toBeTruthy();
  await userEvent.click(screen.getByText(t("table.columns")));
  const columnsControl = screen.getByRole("group", { name: t("table.columns") });
  for (const column of metadataColumns) expect((within(columnsControl).getByRole("checkbox", { name: column.label }) as HTMLInputElement).checked).toBe(false);
  await userEvent.click(within(columnsControl).getByRole("checkbox", { name: "First seen" }));
  expect(within(table).getByRole("columnheader", { name: "First seen" })).toBeTruthy();
  await userEvent.click(within(columnsControl).getByRole("checkbox", { name: "Record unit" }));
  expect(within(table).getByRole("cell", { name: t("file-audit.workspace.saved_4670_groups") })).toBeTruthy();
  expect(within(table).queryByText("saved_event_group")).toBeNull();
  await userEvent.click(await screen.findByText("Synthetic boundary group"));
  const details = screen.getByRole("region", { name: t("file-audit.workspace.evidence") });
  expect(within(details).getByText("retained-group-reference")).toBeTruthy();
  expect(within(details).getByText("42")).toBeTruthy();
  expect(within(details).getByText(`${t("file-audit.workspace.count")}: ${countLabel}`)).toBeTruthy();
  expect(within(details).getByText(t("file-audit.workspace.saved_4670_groups"))).toBeTruthy();
  expect(within(details).getByText(t(groupBoundary === "inside" ? "file-audit.workspace.boundary_inside" : "file-audit.workspace.boundary_overlap"))).toBeTruthy();
  expect(within(details).getAllByText(t("reports.v2.file-audit.permission-changes.columns.correlation_state.labels.not_attempted"))).toHaveLength(1);
  for (const raw of ["saved_event_group", "inside", "overlap", "not_attempted"]) expect(within(details).queryByText(raw)).toBeNull();
  for (const label of ["Minimum", "Maximum"]) expect(Boolean(within(details).queryByText(label))).toBe(groupBoundary === "overlap");
  await userEvent.click(screen.getByRole("button", { name: t("file-audit.workspace.back") }));
  const exported = new URL(screen.getByRole("link", { name: /CSV/ }).getAttribute("href")!, window.location.origin).searchParams;
  for (const key of ["from", "to", "share", "path", "record_unit"]) expect(exported.getAll(key), key).toEqual(target.getAll(key));
  expect(exported.get("from")).toBe("2026-10-23T11:59:37.125Z");
  expect(exported.get("to")).toBe("2026-10-24T11:59:37.125Z");
  expect((screen.getByLabelText(t("period.from")) as HTMLInputElement).validity.valid).toBe(true);
  fireEvent.change(screen.getByLabelText(t("file-audit.workspace.record_unit")), { target: { value: "" } });
  await userEvent.click(screen.getByRole("button", { name: t("filters.apply") }));
  await waitFor(() => expect(mocks.data.mock.calls.at(-1)?.[1].get("record_unit")).toBeNull());
  expect(new URLSearchParams(window.location.search).has("record_unit")).toBe(false);
});


const linkedAgent = "00000000-0000-4000-8000-000000000001";
const agentRows = (agentId: unknown = linkedAgent) => mocks.data.mockImplementation(async (key: string, params: URLSearchParams) => ({
  ...result(key, params), items: [{ id: "audit-source", path: "Synthetic agent source", agent_id: agentId }],
  filtered_count: 1, has_more: false, next_cursor: null,
}));
it.each([["domain=7", "domain=7"], ["domain_id=8", "domain=8"], ["scope=all", "scope=all"]])("opens only the selected audit agent in a new tab and preserves source %s", async (scope, expectedScope) => {
  mocks.access.platform_owner = true;
  window.history.replaceState({}, "", `/app/report/file-audit.audit-state?tab=audit-state&period=24h&path=synthetic-filter&${scope}`);
  agentRows();
  mount();
  await userEvent.click(await screen.findByText("Synthetic agent source"));
  const link = screen.getByRole("link", { name: t("file-audit.open_agent_new_tab") });
  expect(link.getAttribute("href")).toBe(`/app/agents?agent_id=${linkedAgent}&${expectedScope}#agent-${linkedAgent}`);
  expect(link.getAttribute("target")).toBe("_blank");
  expect(link.getAttribute("rel")).toBe("noopener noreferrer");
  const before = window.location.href;
  const requests = mocks.data.mock.calls.length;
  expect(new URLSearchParams(window.location.search).get("path")).toBe("synthetic-filter");
  expect(new URLSearchParams(window.location.search).get("period")).toBe("24h");
  fireEvent.click(link);
  expect(window.location.href).toBe(before);
  expect(mocks.data.mock.calls.length).toBe(requests);
  expect(screen.getByRole("region", { name: t("file-audit.workspace.evidence") })).toBeTruthy();
});
it("does not offer owner-only audit controls to access.manage alone", async () => {
  mocks.access.capabilities.push("access.manage");
  agentRows(); mount();
  await userEvent.click(screen.getByRole("tab", { name: tabTitle("audit-state") }));
  await userEvent.click(await screen.findByText("Synthetic agent source"));
  expect(screen.queryByRole("link", { name: t("file-audit.open_agent_new_tab") })).toBeNull();
});
it.each([undefined, "wrong-id"])("does not link an audit row without an exact agent %s", async (agentId) => {
  mocks.access.platform_owner = true;
  agentRows(agentId === undefined ? null : agentId); mount();
  await userEvent.click(screen.getByRole("tab", { name: tabTitle("audit-state") }));
  await userEvent.click(await screen.findByText("Synthetic agent source"));
  expect(screen.queryByRole("link", { name: t("file-audit.open_agent_new_tab") })).toBeNull();
});
it("does not show the link on action rows and removes it on owner revocation", async () => {
  mocks.access.platform_owner = true;
  agentRows(); const view = mount();
  await userEvent.click(await screen.findByText("Synthetic agent source"));
  expect(screen.queryByRole("link", { name: t("file-audit.open_agent_new_tab") })).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: t("file-audit.workspace.back") }));
  await userEvent.click(screen.getByRole("tab", { name: tabTitle("audit-state") }));
  await userEvent.click(await screen.findByText("Synthetic agent source"));
  expect(screen.getByRole("link", { name: t("file-audit.open_agent_new_tab") })).toBeTruthy();
  mocks.access.platform_owner = false;
  view.rerender(<QueryClientProvider client={client}><FileAuditReport definition={declaration()}/></QueryClientProvider>);
  expect(screen.queryByRole("link", { name: t("file-audit.open_agent_new_tab") })).toBeNull();
});
it("removes the exact-agent link when report access is denied", async () => {
  mocks.access.platform_owner = true;
  agentRows(); mount();
  await userEvent.click(screen.getByRole("tab", { name: tabTitle("audit-state") }));
  await userEvent.click(await screen.findByText("Synthetic agent source"));
  expect(screen.getByRole("link", { name: t("file-audit.open_agent_new_tab") })).toBeTruthy();
  mocks.data.mockRejectedValueOnce(new ApiResponseError(403, "report_access_denied"));
  await userEvent.click(screen.getByRole("button", { name: t("file-audit.workspace.back") }));
  await userEvent.click(screen.getByRole("button", { name: "Применить" }));
  expect(await screen.findByText("Denied")).toBeTruthy();
  expect(screen.queryByRole("link", { name: t("file-audit.open_agent_new_tab") })).toBeNull();
});
it("keeps page two and the frozen window in the source tab when opening an agent", async () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2026-10-26T12:00:00.000Z"));
  mocks.access.platform_owner = true;
  window.history.replaceState({}, "", "/app/report/file-audit.audit-state?tab=audit-state&period=24h&domain=7&path=synthetic-filter");
  mocks.data.mockImplementation(async (key: string, params: URLSearchParams) => {
    const response = result(key, params);
    return { ...response, items: response.items.map((row) => ({ ...row, agent_id: linkedAgent })) };
  });
  mount();
  await screen.findByText("1–50 из 52");
  expect(screen.queryByRole("link", { name: t("file-audit.open_agent_new_tab") })).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Вперёд" }));
  await screen.findByText("51–52 из 52");
  await userEvent.click(screen.getByText("Synthetic object 50"));
  const before = new URLSearchParams(mocks.data.mock.calls.at(-1)![1]);
  const requestCount = mocks.data.mock.calls.length;
  expect(before.get("cursor")).toBe("synthetic-cursor");
  expect(before.get("from")).toBe("2026-10-25T12:00:00.000Z");
  expect(before.get("to")).toBe("2026-10-26T12:00:00.000Z");
  vi.setSystemTime(new Date("2026-10-26T12:05:00.000Z"));
  fireEvent.click(screen.getByRole("link", { name: t("file-audit.open_agent_new_tab") }));
  expect(screen.getByRole("region", { name: t("file-audit.workspace.evidence") })).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: t("file-audit.workspace.back") }));
  expect(screen.getByText("51–52 из 52")).toBeTruthy();
  expect(mocks.data.mock.calls.length).toBe(requestCount);
  const after = mocks.data.mock.calls.at(-1)![1] as URLSearchParams;
  for (const key of ["from", "to", "cursor", "path"]) expect(after.getAll(key)).toEqual(before.getAll(key));
  expect(new URLSearchParams(window.location.search).get("domain")).toBe("7");
});

it.each(["ru", "en"] as const)("names permission masks in %s without changing retained evidence or export", async (locale) => {
  const reload = vi.spyOn(localeRuntime, "reload").mockImplementation(() => {});
  setLocale(locale);
  const source = { id: "rights", path: "Synthetic permissions", details: { share_mask: 0x1301bf, ntfs_mask: 0x1f01ff } };
  const groups = [{ subject_sid: "synthetic-group", smb_mask: 0x120089, ntfs_mask: 0x21f01ff }];
  const maskColumns: ReportDefinitionDto["columns"] = [
    { key: "share_mask", path: "details.share_mask", label: "SMB", kind: "code" },
    { key: "ntfs_mask", path: "details.ntfs_mask", label: "NTFS", kind: "code" },
  ];
  mocks.definition.mockImplementation(async (key: string) => ({ ...declaration(key), columns: [...declaration(key).columns, ...maskColumns], views: [
    { key: "table", kind: "table", source: "items" },
    { key: "groups", kind: "table", source: "groups", title: "Synthetic group assignments", columns: [
      { key: "smb_mask", path: "smb_mask", label: "SMB", kind: "code" },
      { key: "ntfs_mask", path: "ntfs_mask", label: "NTFS", kind: "code" },
    ] },
  ] }));
  mocks.data.mockImplementation(async (key: string, params: URLSearchParams) => ({ ...result(key, params),
    items: [source, { id: "custom", path: "Synthetic custom", details: { share_mask: 0x21f01ff, ntfs_mask: null } },
      { id: "zero", path: "Synthetic zero", details: { share_mask: 0, ntfs_mask: 0x12019f } }],
    collections: { groups }, filtered_count: 3, has_more: false, next_cursor: null,
  }));
  try {
    mount();
    await userEvent.click(screen.getByRole("tab", { name: tabTitle("permissions") }));
    const findings = await screen.findByRole("table", { name: tabTitle("permissions") });
    expect(within(findings).getByText(t("file-audit.permissions.modify"))).toBeTruthy();
    expect(within(findings).getByText(t("file-audit.permissions.full"))).toBeTruthy();
    expect(within(findings).getByText(`${t("file-audit.permissions.custom")} (${0x21f01ff})`)).toBeTruthy();
    expect(within(findings).getByText(t("file-audit.permissions.none"))).toBeTruthy();
    expect(within(findings).getByText(t("file-audit.permissions.read_write"))).toBeTruthy();
    expect(within(findings).getByText("—")).toBeTruthy();
    const groupTable = screen.getByRole("table", { name: "Synthetic group assignments" });
    expect(within(groupTable).getByText(t("file-audit.permissions.read"))).toBeTruthy();
    expect(within(groupTable).getByText(`${t("file-audit.permissions.custom")} (${0x21f01ff})`)).toBeTruthy();
    await userEvent.click(within(findings).getByText("Synthetic permissions"));
    const drawer = screen.getByRole("region", { name: t("file-audit.workspace.evidence") });
    expect(within(drawer).getByText("1245631")).toBeTruthy();
    expect(within(drawer).getByText("2032127")).toBeTruthy();
    expect(source.details).toEqual({ share_mask: 1245631, ntfs_mask: 2032127 });
    expect(groups[0].ntfs_mask).toBe(0x21f01ff);
    await userEvent.click(screen.getByRole("button", { name: t("file-audit.workspace.back") }));
    // Export remains the server endpoint, not a localized client-side dataset.
    expect(screen.getByRole("link", { name: /CSV/ }).getAttribute("href")).toContain("/file-audit.permissions/export.csv?");
  } finally {
    setLocale("ru");
    reload.mockRestore();
  }
});

it.each(["ru", "en"] as const)("preserves main audit controls and evidence without collection notes (%s)", async (locale) => {
  const reload = vi.spyOn(localeRuntime, "reload").mockImplementation(() => {});
  setLocale(locale);
  mocks.definition.mockImplementation(async (key: string) => ({ ...declaration(key), columns: [...declaration(key).columns,
    { key: "delivery_record_id", path: "delivery_record_id", label: "RecordID", kind: "number" },
    { key: "unread_objects", path: "unread_objects", label: "Unread", kind: "number" },
  ], views: [{ key: "groups", kind: "table", source: "groups", title: "Synthetic empty groups", note: "Synthetic collection note" }] }));
  mocks.data.mockImplementation(async (key: string, params: URLSearchParams) => ({ ...result(key, params),
    items: [{ id: "audit", path: "Synthetic audited root", delivery_record_id: 12345, unread_objects: 0 }],
    collections: { groups: [] }, limitations: [{ code: "synthetic", text: "Synthetic limitation" }],
  }));
  try {
    mount();
    await userEvent.click(screen.getByRole("tab", { name: tabTitle("audit-state") }));
    const table = await screen.findByRole("table", { name: tabTitle("audit-state") });
    const form = screen.getByRole("form", { name: t("filters.title") });
    expect(form.closest("details")).toBeNull();
    expect(within(form).getByRole("button", { name: t("filters.apply") })).toBeTruthy();
    expect(screen.getByText("UTC")).toBeTruthy();
    expect(within(table).getByText("RecordID")).toBeTruthy();
    expect(within(table).getByText(t("file-audit.workspace.scan_gaps"))).toBeTruthy();
    expect(screen.getByText(t("file-audit.audit_scope_note"))).toBeTruthy();
    expect(screen.getByText("Synthetic limitation").closest("details")).toBeNull();
    const collection = screen.getByRole("region", { name: "Synthetic empty groups" });
    expect(screen.queryByText("Synthetic collection note")).toBeNull();
    expect(collection.querySelector(".sli-ds-state--banner")).toBeNull();
    expect(within(collection).getByRole("status")).toBeTruthy();
  } finally { setLocale("ru"); reload.mockRestore(); }
});

it.each(["__proto__", "constructor", "toString"])("preserves unknown SID text %s in primary and group rows", async (subject) => {
  mocks.definition.mockImplementation(async (key: string) => ({ ...declaration(key), columns: [
    { key: "employee", path: "employee", label: "Subject", kind: "text" },
  ], views: [{ key: "groups", kind: "table", source: "groups", title: "Groups", columns: [
    { key: "subject_sid", path: "subject_sid", label: "Group", kind: "text" },
  ] }] }));
  mocks.data.mockImplementation(async (key: string, params: URLSearchParams) => ({ ...result(key, params),
    items: [{ id: "unknown", employee: subject }], collections: { groups: [{ subject_sid: subject }] },
  }));
  mount(); await userEvent.click(screen.getByRole("tab", { name: tabTitle("permissions") }));
  const primary = await screen.findByRole("table", { name: tabTitle("permissions") });
  expect(within(primary).getByText(subject)).toBeTruthy();
  expect(within(screen.getByRole("table", { name: "Groups" })).getByText(subject)).toBeTruthy();
});

it.each(["ru", "en"] as const)("keeps one file-audit tab bar and legacy workspace links in %s", async (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => {});
  setLocale(locale);
  window.history.replaceState({}, "", "/app/report/file-audit.overview?nav_view=permissions");
  mount();
  const tab = await screen.findByRole("tab", { name: tabTitle("permissions") });
  await waitFor(() => expect(mocks.data.mock.calls.some(([key]) => key === "file-audit.permissions")).toBe(true));
  expect(screen.getAllByRole("tablist")).toHaveLength(1);
  expect(tab.getAttribute("aria-selected")).toBe("true");
  setLocale("ru");
  vi.restoreAllMocks();
});

function mountUnconfiguredAudit(search = "", failure?: ApiResponseError) {
  const key = "file-audit.overview";
  window.history.replaceState({}, "", "/app/report/" + key + search);
  mocks.data.mockImplementation(async (report: string, params: URLSearchParams) => ({
    ...result(report, params), state: "not_collected", items: [], filtered_count: null, has_more: false, next_cursor: null,
  }));
  if (failure) mocks.data.mockRejectedValue(failure);
  mount(declaration(key));
}

it("links the owner to the existing configuration for an unconfigured File Audit overview", async () => {
  mocks.access.platform_owner = true;
  mountUnconfiguredAudit();
  const action = await screen.findByRole("link", { name: t("pluginPage.configure") });
  expect(action.getAttribute("href")).toBe("/app/admin/plugins/sli.file-audit");
  expect(screen.getAllByRole("link", { name: t("pluginPage.configure") })).toEqual([action]);
});

it.each(["?scope=all", "?domain_id=7", "?path=synthetic", "?source_kind=server", "?share=synthetic"])(
  "keeps the scoped or filtered File Audit overview with %s", async search => {
    mocks.access.platform_owner = true;
    mountUnconfiguredAudit(search);
    await waitFor(() => expect(client.isFetching()).toBe(0));
    expect(mocks.data).toHaveBeenCalled();
    expect(mocks.agents).not.toHaveBeenCalled();
    expect(screen.queryByRole("link", { name: t("pluginPage.configure") })).toBeNull();
  },
);

it("keeps a File Audit report without an action when a configured agent already exists", async () => {
  mocks.access.platform_owner = true;
  mocks.agents.mockResolvedValue({ items: [{ assigned_modules: [{ module_id: "sli.file-audit", enabled: true }] }] });
  mountUnconfiguredAudit();
  await waitFor(() => expect(mocks.agents).toHaveBeenCalled());
  await waitFor(() => expect(client.isFetching()).toBe(0));
  expect(screen.queryByRole("link", { name: t("pluginPage.configure") })).toBeNull();
});

it("does not expose setup after a File Audit report denial", async () => {
  mocks.access.platform_owner = true;
  mountUnconfiguredAudit("", new ApiResponseError(403, "domain_scope_denied"));
  expect(await screen.findByText("Denied")).toBeTruthy();
  expect(mocks.agents).not.toHaveBeenCalled();
  expect(screen.queryByRole("link", { name: t("pluginPage.configure") })).toBeNull();
});

it.each([
  ["viewer", [], false],
  ["admin", [{ mode: "restricted", clauses: [{ device_ids: ["synthetic"] }] }], false],
  ["admin", [{ kind: "all" }], true],
] as const)("checks File Audit management and report scope for %s (%j)", async (role, scopes, allowed) => {
  mocks.access.subject.coarse_role = role;
  if (role === "admin") mocks.access.capabilities.push("access.manage", "operations.view", "file-audit.audit.manage");
  mocks.access.reports.find(report => report.report_key === "file-audit.overview")!.scopes = [...scopes];
  mountUnconfiguredAudit();
  if (allowed) {
    expect(await screen.findByRole("link", { name: t("pluginPage.configure") })).toBeTruthy();
  } else {
    await waitFor(() => expect(client.isFetching()).toBe(0));
    expect(mocks.data).toHaveBeenCalled();
    expect(mocks.agents).not.toHaveBeenCalled();
    expect(screen.queryByRole("link", { name: t("pluginPage.configure") })).toBeNull();
  }
});
