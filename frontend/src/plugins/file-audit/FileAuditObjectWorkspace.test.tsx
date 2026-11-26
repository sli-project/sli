// @vitest-environment jsdom
import { chooseOption } from "../../../tests/select-option";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { FileAuditObjectWorkspace } from "./FileAuditObjectWorkspace";
import { FileAuditComparison } from "./FileAuditComparison";
import type { FileAuditDetailResult, FileAuditObservation } from "./acl";
import { t } from "../../i18n";

const state = vi.hoisted(() => ({ detail: vi.fn(), access: { reports: [{ report_key: "file-audit.permissions", allowed: true }] } }));
vi.mock("../../api/client", async original => ({ ...await original<typeof import("../../api/client")>(), api: { reportV2Detail: state.detail } }));
vi.mock("../../app/App", () => ({ useEffectiveAccess: () => state.access }));
vi.mock("../../app/report-v2/ReportDenied", () => ({ ReportDenied: () => <p role="alert">Denied</p> }));
const snapshot = "00000000-0000-4000-8000-000000000001";
const share = JSON.stringify(["fixture-agent", "fixture-source", "fixture-root"]);
const path = "D:\\Synthetic\\Reports";
const observation = (): FileAuditObservation => ({
  snapshot: { id: snapshot, observed_at: "2026-11-24T10:00:00Z", policy_revision: "4", scan_id: "fixture-scan", page_number: 0, has_more: false, completeness: "complete", unread_objects: 0 },
  share: { name: "Reports", path: "D:\\Synthetic", complete: true, dacl: { state: "complete", raw: "D:", flags_raw: "", aces: [] } },
  object: { path, object_type: "directory", owner_sid: "S-1-5-18", file_id: "fixture-file", sacl_protected: false,
    dacl: { state: "complete", raw: "retained-source-dacl", flags_raw: "", aces: Array.from({ length: 126 }, (_, ordinal) => ({
      ordinal, type: ordinal === 125 ? "unknown" : "allow", ace_type: ordinal === 125 ? "XA" : "A",
      sid: `S-1-5-21-1-${1000 + ordinal}`, mask: ordinal === 125 ? null : 0x120089, mask_raw: ordinal === 125 ? "conditional-mask" : "0x120089",
      flags: ordinal >= 100 ? ["ID", "CI"] : [], flags_raw: ordinal >= 100 ? "IDCI" : "",
      inherited: ordinal >= 100, inherit_only: false, raw: `retained-ace-${ordinal}`,
    })) }, sacl: { state: "missing", raw: null, aces: [] } },
});
const response = (): FileAuditDetailResult => ({
  contract_id: "sli.report-result.v2", report_key: "file-audit.permissions", state: "ok", items: [], has_more: false, next_cursor: null,
  filtered_count: 0, metrics: [], series: {}, coverage: {}, filter_options: {}, limitations: [], window: {},
  detail: { ...observation(), comparison: { state: "not_requested", reason: null, identity_basis: null } },
  collections: { objects: [{ id: "child", path }], snapshots: [{ id: snapshot, observed_at: "2026-11-24T10:00:00Z" }] },
});
let client: QueryClient;
const props = () => ({ snapshotId: snapshot, objectPath: path,
  params: new URLSearchParams({ share, path, tab: "permissions", object_path: path, return_to: "/app/report/file-audit.overview", tz: "UTC" }).toString(),
  backHref: "/app/report/file-audit.overview", session: "fixture-access", pageSize: 50 });
function mount() {
  client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(<QueryClientProvider client={client}><FileAuditObjectWorkspace {...props()}/></QueryClientProvider>);
}
beforeEach(() => {
  window.history.replaceState({}, "", `/app/report/file-audit.permissions?${new URLSearchParams({ share, snapshot_id: snapshot, object_path: path })}`);
  state.access.reports[0].allowed = true;
  state.detail.mockReset().mockImplementation(async () => response());
});
afterEach(() => { cleanup(); client?.clear(); });

it("pages and searches the entire retained ACL and preserves unknown ACE types", async () => {
  mount();
  const acl = within(await screen.findByRole("region", { name: t("file-audit.acl.ntfs") }));
  expect(acl.getAllByRole("row")).toHaveLength(51);
  fireEvent.click(acl.getByRole("radio", { name: "200" }));
  expect(acl.getAllByRole("row")).toHaveLength(127);
  fireEvent.change(acl.getByLabelText(t("file-audit.acl.search")), { target: { value: "S-1-5-21-1-1125" } });
  await chooseOption(acl.getByLabelText(t("file-audit.acl.filter"), { selector: "button" }), "inherited");
  expect(acl.getAllByRole("row")).toHaveLength(2);
  expect(acl.getByText("Тип XA")).toBeTruthy();
  await userEvent.click(acl.getByText("S-1-5-21-1-1125"));
  expect(acl.getByText("retained-ace-125")).toBeTruthy();
  const sent = state.detail.mock.calls[0][2] as URLSearchParams;
  expect(sent.getAll("share")).toEqual([share]);
  expect(sent.get("path")).toBe(path);
  expect(sent.has("return_to")).toBe(false);
  expect(sent.has("object_path")).toBe(false);
});

it("removes retained ACL values and object identity when permission access is revoked", async () => {
  const view = mount();
  await screen.findByRole("table", { name: t("file-audit.acl.ntfs") });
  state.access.reports[0].allowed = false;
  view.rerender(<QueryClientProvider client={client}><FileAuditObjectWorkspace {...props()}/></QueryClientProvider>);
  expect(await screen.findByText("Denied")).toBeTruthy();
  expect(screen.queryByRole("table")).toBeNull();
  expect(screen.queryByText(path)).toBeNull();
  expect(screen.queryByText("retained-source-dacl")).toBeNull();
});

it("keeps observed-object navigation when the requested root is missing from this snapshot page", async () => {
  state.detail.mockImplementation(async (_key: string, _id: string, params: URLSearchParams) => {
    const item = response();
    if (params.get("path") === path) item.detail!.object = null;
    else item.detail!.object!.path = `${path}\\Retained`;
    item.collections!.objects = [{ id: "retained", path: `${path}\\Retained` }];
    return item;
  });
  mount();
  await screen.findByText(t("file-audit.workspace.snapshot_missing"));
  await userEvent.click(screen.getByRole("button", { name: `${path}\\Retained` }));
  await screen.findByRole("table", { name: t("file-audit.acl.ntfs") });
  expect((state.detail.mock.calls.at(-1)![2] as URLSearchParams).get("path")).toBe(`${path}\\Retained`);
});

it("shows ACL header flag differences and keeps owner comparison separate from DACL", async () => {
  const before = observation(), after = observation();
  after.object!.dacl.flags_raw = "P";
  after.object!.owner_sid = "S-1-5-32-544";
  render(<FileAuditComparison comparison={{ state: "available", reason: null, identity_basis: "path", before, after }} pageSize={50}/>);
  expect(screen.getByText(t("file-audit.compare.identity_path"))).toBeTruthy();
  expect(screen.getByText("P")).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: t("file-audit.workspace.owner") }));
  expect(screen.getByText("S-1-5-18")).toBeTruthy();
  expect(screen.getByText("S-1-5-32-544")).toBeTruthy();
  expect(screen.queryByText("retained-source-dacl")).toBeNull();
});
