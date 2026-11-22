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
    const data = { contract_id: "sli.report-result.v2", report_key: "ad.gpo.v2", state: "partial",
      items: id ? [] : policies, collections: !id ? {} : history ? { changes } : details,
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

