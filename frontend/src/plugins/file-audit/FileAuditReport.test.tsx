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

const mocks = vi.hoisted(() => ({ definition: vi.fn(), data: vi.fn(), access: {
  platform_owner: false,
  subject: { type: "user", id: 1 }, evaluated_at_utc: "synthetic-evaluation", capabilities: ["file-audit.view", "file-audit.export"],
  reports: ["overview", "actions", "mass-operations", "permission-changes", "access-denials", "out-of-hours", "permissions", "audit-state"].map((key) => ({
    report_key: `file-audit.${key}`, allowed: true, allowed_actions: ["view", "export"],
  })),
} }));
vi.mock("../../api/client", async (importOriginal) => ({ ...await importOriginal<typeof import("../../api/client")>(),
  api: { reportV2Definition: mocks.definition, reportV2Data: mocks.data } }));
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
function mount() {
  client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(<QueryClientProvider client={client}><FileAuditReport definition={declaration()}/></QueryClientProvider>);
}
beforeEach(() => {
  window.history.replaceState({}, "", "/app/report/file-audit.actions");
  mocks.definition.mockReset().mockImplementation(async (key: string) => declaration(key));
  mocks.data.mockReset().mockImplementation(async (key: string, params: URLSearchParams) => result(key, params));
  mocks.access.capabilities = ["file-audit.view", "file-audit.export"];
  mocks.access.platform_owner = false;
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
  expect(within(form).getAllByRole("combobox", { name: "Шара" })).toHaveLength(1);
  expect(within(form).getByLabelText("Сотрудник")).toBeTruthy();
  expect(within(form).getByLabelText("Действие")).toBeTruthy();
  expect(within(form).getByLabelText("Объект").closest(".sli-ds-field")?.getAttribute("data-wide")).toBe("true");
  expect(within(form).getByLabelText("Включая вложенные")).toBeTruthy();
  expect(form.querySelector(".sli-ds-filters__fields")?.getAttribute("data-layout")).toBe("grid");
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
  fireEvent.change(screen.getByLabelText("Сотрудник"), { target: { value: "synthetic-user" } });
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

it("hides prior rows, drawer and export when a tab denies access", async () => {
  mount();
  await userEvent.click(await screen.findByText("Synthetic object 0"));
  expect(screen.getByRole("dialog")).toBeTruthy();
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
  expect(screen.getByText("Synthetic metric").closest(".sli-ds-metric")?.textContent).toContain("—");
  expect(screen.queryByText("0–0 из 0")).toBeNull();
});

it("keeps export hidden without its independent capability", async () => {
  mocks.access.capabilities = ["file-audit.view"];
  mount();
  await screen.findByText("1–50 из 52");
  expect(screen.queryByRole("link", { name: /CSV/ })).toBeNull();
});

it("keeps the counter's relative window through filtered actions, source evidence and back until Apply", async () => {
  // Only Date is fake: React Query and userEvent keep their real scheduling.
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2026-10-24T12:00:00.000Z"));
  const scope = new URLSearchParams({ tab: "overview", period: "24h", source_kind: "server",
    path: "C:\\Synthetic\\Folder", include_nested: "false", employee: "synthetic-user", share: "synthetic-share" });
  window.history.replaceState({}, "", `/app/report/file-audit.overview?${scope}`);
  mocks.definition.mockImplementation(async (key: string): Promise<ReportDefinitionDto> => ({
    ...declaration(key),
    params: declaration(key).params.map((param) => param.key === "operation"
      ? { ...param, options: [{ value: "read", label: "Чтение" }] } : param),
    detail: { kind: "inline", title: "Synthetic retained evidence", key: "id", inline: "evidence", row_links: [], columns: [
      { key: "reference", path: "reference", label: "Reference", kind: "code" },
      { key: "event_id", path: "event_id", label: "Event", kind: "number" },
      { key: "record_id", path: "record_id", label: "Record", kind: "number" },
      { key: "path", path: "path", label: "Source object", kind: "text" },
      { key: "payload_sha256", path: "payload_sha256", label: "Hash", kind: "code" },
    ] },
  }));
  const boundary = "2026-10-23T12:00:30.000Z";
  mocks.data.mockImplementation(async (key: string, params: URLSearchParams): Promise<ReportResultDto> => {
    const response = { ...result(key, params), filter_options: { share: [{ value: "synthetic-share", label: "Synthetic share" }] } };
    if (key === "file-audit.overview") return { ...response,
      metrics: [{ key: "read", label: "Synthetic reads", value: 1, quality: "observed", filter: { operation: "read" } }],
    };
    // A synthetic retained boundary event disappears if navigation advances the window.
    const included = params.get("operation") === "read" && params.get("from")! <= boundary && boundary < params.get("to")!;
    return { ...response, items: included ? [{ id: "boundary-action", path: "Synthetic boundary action", evidence: [{
      reference: "synthetic-source-reference", event_id: 4663, record_id: 42,
      path: "C:\\Synthetic\\Folder", payload_sha256: "a".repeat(64),
    }] }] : [], filtered_count: included ? 1 : 0, has_more: false, next_cursor: null };
  });
  mount();
  await screen.findByRole("button", { name: /Synthetic reads/ });
  await userEvent.click(screen.getByRole("button", { name: "Вперёд" }));
  await screen.findByText("51–52 из 52");
  const overviewParams = new URLSearchParams(mocks.data.mock.calls.at(-1)![1]);
  expect(overviewParams.get("from")).toBe("2026-10-23T12:00:00.000Z");
  expect(overviewParams.get("to")).toBe("2026-10-24T12:00:00.000Z");
  expect(overviewParams.get("cursor")).toBe("synthetic-cursor");

  vi.setSystemTime(new Date("2026-10-24T12:05:00.000Z"));
  await userEvent.click(screen.getByRole("button", { name: /Synthetic reads/ }));
  await waitFor(() => expect(mocks.data.mock.calls.at(-1)?.[0]).toBe("file-audit.actions"));
  const actionsParams = new URLSearchParams(mocks.data.mock.calls.at(-1)![1]);
  for (const key of ["from", "to", "source_kind", "path", "include_nested", "employee", "share", "tz"]) {
    expect(actionsParams.getAll(key), key).toEqual(overviewParams.getAll(key));
  }
  expect(actionsParams.get("operation")).toBe("read");
  expect(actionsParams.get("cursor")).toBeNull();
  await screen.findByText("1–1 из 1");
  await userEvent.click(screen.getByText("Synthetic boundary action"));
  const evidence = within(screen.getByRole("dialog")).getByRole("table", { name: "Synthetic retained evidence" });
  expect(within(evidence).getByText("synthetic-source-reference")).toBeTruthy();
  expect(within(evidence).getByText("42")).toBeTruthy();
  expect(within(evidence).getByText("C:\\Synthetic\\Folder")).toBeTruthy();
  expect(within(evidence).getByText("a".repeat(64))).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: t("drawer.close") }));
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(screen.getByText("1–1 из 1")).toBeTruthy();
  const exportParams = new URL(screen.getByRole("link", { name: /CSV/ }).getAttribute("href")!, window.location.origin).searchParams;
  expect(exportParams.get("from")).toBe(actionsParams.get("from"));
  expect(exportParams.get("to")).toBe(actionsParams.get("to"));
  expect(exportParams.get("operation")).toBe("read");

  await userEvent.click(screen.getByRole("button", { name: "Применить" }));
  await waitFor(() => expect(mocks.data.mock.calls.at(-1)?.[1].get("to")).toBe("2026-10-24T12:05:00.000Z"));
  expect(mocks.data.mock.calls.at(-1)?.[1].get("from")).toBe("2026-10-23T12:05:00.000Z");
  await screen.findByText("0–0 из 0");
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
  expect(screen.getByRole("dialog")).toBeTruthy();
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
  await userEvent.click(screen.getByRole("button", { name: t("drawer.close") }));
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
  await userEvent.click(screen.getByRole("button", { name: t("drawer.close") }));
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
  expect(screen.getByText("51–52 из 52")).toBeTruthy();
  expect(screen.getByRole("dialog")).toBeTruthy();
  expect(mocks.data.mock.calls.length).toBe(requestCount);
  const after = mocks.data.mock.calls.at(-1)![1] as URLSearchParams;
  for (const key of ["from", "to", "cursor", "path"]) expect(after.getAll(key)).toEqual(before.getAll(key));
  expect(new URLSearchParams(window.location.search).get("domain")).toBe("7");
});

it.each(["ru", "en"] as const)("names permission masks in %s without changing drawer evidence or export", async (locale) => {
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
    const drawer = screen.getByRole("dialog");
    expect(within(drawer).getByText("1245631")).toBeTruthy();
    expect(within(drawer).getByText("2032127")).toBeTruthy();
    expect(source.details).toEqual({ share_mask: 1245631, ntfs_mask: 2032127 });
    expect(groups[0].ntfs_mask).toBe(0x21f01ff);
    // Export remains the server endpoint, not a localized client-side dataset.
    expect(screen.getByRole("link", { name: /CSV/ }).getAttribute("href")).toContain("/file-audit.permissions/export.csv?");
  } finally {
    setLocale("ru");
    reload.mockRestore();
  }
});

it.each(["ru", "en"] as const)("preserves main audit controls, retention and evidence without collection notes (%s)", async (locale) => {
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
    expect(within(table).getByText("Unread")).toBeTruthy();
    const retention = within(screen.getByRole("heading", { name: t("file-audit.retention") }).closest("section")!);
    expect(screen.getByText(t("file-audit.audit_scope_note"))).toBeTruthy();
    for (const suffix of ["payload", "facts", "acl"] as const) {
      expect(retention.getByText(t(`file-audit.retention.${suffix}`))).toBeTruthy();
      expect(retention.getByText(t(`file-audit.retention.${suffix}_value`))).toBeTruthy();
    }
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
