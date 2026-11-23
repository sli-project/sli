// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { localeRuntime, setLocale } from "../../i18n";
import { ReportRenderer } from "../../app/report-v2/ReportRenderer";
import gpoDeclaration from "../../../../server-dotnet/src/Sli.Server/Gpo/declaration.json";

const older = "2026-11-21T12:00:00Z";
const newer = "2026-11-22T02:00:00Z";
const policies = [
  { id: "linked", display_name: "Linked policy", modification_time: older, link_count: 2, setting_count: 3,
    computer_directory_version: 7, computer_sysvol_version: 7 },
  { id: "updated", display_name: "Updated policy", modification_time: newer, link_count: 0, setting_count: 1,
    computer_directory_version: 12, computer_sysvol_version: 11, unlinked: true },
  { id: "unobserved", display_name: "Unobserved links", modification_time: older, link_count: null,
    computer_directory_version: 7, computer_sysvol_version: null },
];
const snapshot = { observed_at: newer, computer_directory_version: 7, computer_sysvol_version: 7 };
const details = {
  settings: [
    { id: "timeout", side: "computer", setting_name: "Timeout", path: "Security/Screen lock", category: "Security", value_display: "600 seconds" },
    { id: "audit", side: "computer", setting_name: "Audit", category: "Logging", value_display: "<img src=x>" },
    { id: "theme", side: "user", setting_name: "Theme", category: "Desktop", value_display: "Enabled" },
  ],
  links: [{ id: "link", scope_name: "Workstations", order: 1, enabled: true, enforced: false }],
  permissions: [{ id: "permission", trustee_name: "Domain Admins", permission: "GpoEditDeleteModifySecurity" }],
  versions: [snapshot, { ...snapshot, observed_at: older, computer_directory_version: 6, computer_sysvol_version: 6 }],
};
const changes = [{ id: "change", object_id: "timeout", object_type: "gpo_setting", field: "value_display", kind: "attribute_changed",
  name: "Timeout", observed_at: newer, before_value: "900 seconds", after_value: "600 seconds" }];
const snapshots = [
  { id: "snapshot-4", observed_at: newer }, { id: "snapshot-3", observed_at: older },
  { id: "snapshot-2", observed_at: "2026-11-20T12:00:00Z" }, { id: "snapshot-1", observed_at: "2026-11-19T12:00:00Z" },
];
const comparison = [
  { id: "change-1", side: "computer", setting_name: "Timeout", path: "Security/Timeout", kind: "changed", before_value: "900 seconds", after_value: "600 seconds" },
  { id: "change-2", side: "user", setting_name: "Theme", path: "Desktop/Theme", kind: "added", after_value: "Enabled" },
  { id: "change-3", side: "user", setting_name: "Wallpaper", path: "Desktop/Wallpaper", kind: "removed", before_value: "<img src=x>" },
];
const requests: URL[] = [];

beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("en");
  requests.length = 0;
  window.history.replaceState(null, "", "/app/report/ad.gpo.v2?domain=7");
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = new URL(String(input), window.location.origin);
    requests.push(url);
    const id = url.searchParams.get("policy_id");
    const history = id && url.searchParams.get("tab") === "changes";
    const snapshotList = url.searchParams.has("snapshots");
    const before = url.searchParams.get("before_snapshot");
    const data = { contract_id: "sli.report-result.v2", report_key: "ad.gpo.v2", state: "partial",
      items: id ? [] : policies, collections: !id ? {} : history ? { changes } :
        snapshotList ? { snapshots: id === "linked" ? snapshots : snapshots.slice(0, 1) } :
          before ? { snapshot_comparison: before === "snapshot-2" ? [] : comparison } : details,
      has_more: false, next_cursor: null, series: {}, window: {}, metrics: [], filter_options: {},
      coverage: { observed_at_utc: newer, policy_history_state: history ? "ok" : undefined },
      limitations: [{ code: "fixture", text: "Removed collection explanation" }],
    };
    return new Response(JSON.stringify(url.pathname.endsWith("/data") ? data : { ...gpoDeclaration.declaration, filter_options: {} }),
      { headers: { "Content-Type": "application/json" } });
  }));
});
afterEach(() => { cleanup(); setLocale("ru"); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

function renderReport() {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <ReportRenderer reportKey="ad.gpo.v2"/>
  </QueryClientProvider>);
}

it("sorts recent changes first and combines search with counted filters", async () => {
  renderReport();
  const table = await screen.findByRole("table", { name: "Group Policies" });
  expect(within(table).getAllByRole("row")[1].textContent).toContain("Updated policy");
  expect(requests.find((url) => url.pathname.endsWith("/data"))?.searchParams.get("domain")).toBe("7");
  expect(screen.queryByText("Removed collection explanation")).toBeNull();
  expect(within(table).getByRole("link", { name: "12 / 11" }).getAttribute("href")).toBe("/app/report/ad.infrastructure?domain=7");
  fireEvent.click(screen.getByRole("button", { name: "Version mismatch 1" }));
  fireEvent.click(screen.getByRole("button", { name: "Unlinked 1" }));
  expect(within(table).getAllByRole("row")).toHaveLength(2);
  const exportUrl = new URL(screen.getByRole("link", { name: "Export CSV" }).getAttribute("href")!, window.location.origin);
  expect(exportUrl.searchParams.get("view")).toBe("unlinked_version_mismatch");
  fireEvent.change(screen.getByRole("searchbox", { name: "Policy name" }), { target: { value: "Unobserved" } });
  expect(screen.getByRole("button", { name: "Version mismatch 0" })).toBeTruthy();
  expect(screen.getByRole("button", { name: "Unlinked 0" })).toBeTruthy();
  expect(within(table).queryByText("Unobserved links")).toBeNull();
});

it("opens a policy beneath the list and navigates its sections, versions, and changes", async () => {
  renderReport();
  fireEvent.click(await screen.findByRole("button", { name: "Linked policy: 2 links" }));
  const card = screen.getByRole("region", { name: "Linked policy" });
  expect(await within(card).findByText("Workstations")).toBeTruthy();
  fireEvent.click(within(card).getByRole("tab", { name: "Permissions" }));
  expect(within(card).getByText("Edit, delete, and modify permissions")).toBeTruthy();
  fireEvent.click(within(card).getByRole("tab", { name: "Versions" }));
  expect(within(within(card).getByRole("table", { name: "Version history" })).getByText("6 / 6")).toBeTruthy();
  fireEvent.click(await within(card).findByRole("tab", { name: "Changes 1" }));
  expect(within(card).getByText("900 seconds →", { exact: false })).toBeTruthy();
  expect(within(card).getByText("600 seconds")).toBeTruthy();
  const divider = screen.getByRole("separator", { name: "Resize policy list" });
  fireEvent.keyDown(divider, { key: "ArrowUp" });
  expect(divider.getAttribute("aria-valuenow")).toBe("35");
  fireEvent.click(within(card).getByRole("button", { name: "Open full page" }));
  expect(screen.queryByRole("table", { name: "Group Policies" })).toBeNull();
  fireEvent.click(within(card).getByRole("button", { name: "Restore list" }));
  expect(screen.getByRole("table", { name: "Group Policies" })).toBeTruthy();
  fireEvent.click(within(card).getByRole("button", { name: "Close" }));
  expect(screen.queryByRole("region", { name: "Linked policy" })).toBeNull();
});

it("finds settings by path and value, expands history inline, and renders host values as text", async () => {
  renderReport();
  fireEvent.click(await screen.findByRole("button", { name: "Linked policy: 3 settings" }));
  const card = screen.getByRole("region", { name: "Linked policy" });
  const search = await within(card).findByRole("searchbox", { name: "Search by name, path, and value" });
  fireEvent.change(search, { target: { value: "Screen lock" } });
  const timeout = within(card).getByRole("button", { name: "Timeout" });
  fireEvent.click(timeout);
  expect(timeout.getAttribute("aria-expanded")).toBe("true");
  expect(within(card).getByText("Security/Screen lock")).toBeTruthy();
  expect(await within(card).findByText(/was 900 seconds/)).toBeTruthy();
  fireEvent.change(search, { target: { value: "<img" } });
  expect(within(card).getByText("<img src=x>")).toBeTruthy();
  expect(card.querySelector("img")).toBeNull();
  fireEvent.change(search, { target: { value: "" } });
  fireEvent.change(within(card).getByRole("combobox", { name: "Category" }), { target: { value: "Logging" } });
  expect(within(card).queryByText("Timeout")).toBeNull();
  fireEvent.click(within(card).getByRole("button", { name: "User 1" }));
  expect(within(card).getByRole("button", { name: "Theme" })).toBeTruthy();
});

it("compares either of two selected dates in the policy card and distinguishes an equal pair", async () => {
  renderReport();
  fireEvent.click(await screen.findByRole("button", { name: "Linked policy: 2 links" }));
  const card = within(screen.getByRole("region", { name: "Linked policy" }));
  fireEvent.click(card.getByRole("tab", { name: "Versions" }));
  const before = await card.findByRole("combobox", { name: "Before" });
  const after = card.getByRole("combobox", { name: "After" });
  expect(within(before).getAllByRole("option")).toHaveLength(4);
  expect(within(before).getAllByRole("option")[0].textContent).not.toMatch(/snapshot-/);
  const run = card.getByRole("button", { name: "Compare snapshots" });
  fireEvent.change(before, { target: { value: "snapshot-1" } });
  fireEvent.change(after, { target: { value: "snapshot-3" } });
  fireEvent.click(run);
  const result = within(await card.findByRole("table", { name: "Snapshot comparison" }));
  expect(result.getByRole("row", { name: /Timeout.*Changed.*900 seconds.*600 seconds/ })).toBeTruthy();
  expect(result.getByRole("row", { name: /Theme.*Added.*Enabled/ })).toBeTruthy();
  expect(result.getByRole("row", { name: /Wallpaper.*Removed.*<img src=x>/ })).toBeTruthy();
  expect(card.queryByRole("img")).toBeNull();
  const request = requests.find((url) => url.searchParams.has("before_snapshot"))!;
  expect(Object.fromEntries(request.searchParams)).toMatchObject({ policy_id: "linked", domain: "7", before_snapshot: "snapshot-1", after_snapshot: "snapshot-3" });
  fireEvent.change(before, { target: { value: "snapshot-2" } });
  expect(card.queryByRole("table", { name: "Snapshot comparison" })).toBeNull();
  fireEvent.click(run);
  expect(await card.findByText("No differences in visible settings")).toBeTruthy();
});

it("keeps versions visible when a policy has fewer than two comparable snapshots", async () => {
  renderReport();
  const card = within(await screen.findByRole("region", { name: "Updated policy" }));
  fireEvent.click(card.getByRole("tab", { name: "Versions" }));
  expect(await card.findByText("Two snapshots are required for comparison")).toBeTruthy();
  expect(card.getByRole("table", { name: "Version history" })).toBeTruthy();
  expect(card.queryByRole("button", { name: "Compare snapshots" })).toBeNull();
});

