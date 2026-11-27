// @vitest-environment jsdom
import { chooseOption } from "../../../tests/select-option";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { localeRuntime, setLocale } from "../../i18n";
import { ReportRenderer } from "../../app/report-v2/ReportRenderer";
import gpoDeclaration from "../../../../server-dotnet/src/Sli.Server/Gpo/declaration.json";

const older = "2026-11-21T12:00:00Z";
const newer = "2026-11-22T02:00:00Z";
const policies = [
  { id: "linked", display_name: "Linked policy", guid: "b0be2c76-bdae-4110-a727-6158b8f606d3", modification_time: older, link_count: 2, setting_count: 3,
    computer_directory_version: 7, computer_sysvol_version: 7 },
  { id: "updated", display_name: "Updated policy", modification_time: newer, link_count: 0, setting_count: 1,
    guid: "b0be2c76-bdae-4110-a727-6158b8f606d4",
    computer_directory_version: 12, computer_sysvol_version: 11, unlinked: true },
  { id: "unobserved", display_name: "Unobserved links", modification_time: older, link_count: null,
    guid: "b0be2c76-bdae-4110-a727-6158b8f606d5",
    computer_directory_version: 7, computer_sysvol_version: null },
];
const snapshot = { observed_at: newer, computer_directory_version: 7, computer_sysvol_version: 7 };
const auditGuid = "{0CCE9215-69AE-11D9-BED3-505054503030}";
const details = {
  settings: [
    { id: "timeout", side: "computer", setting_name: "Timeout", path: "Security/Screen lock", category: "Security", value_display: "600 seconds" },
    { id: "audit", side: "computer", setting_name: "Audit", category: "Logging", value_display: "<img src=x>" },
    { id: "audit-subcategory", side: "computer", setting_name: "SubcategoryGuid", path: "AuditSetting/SubcategoryGuid", category: "AuditSetting", value_display: auditGuid, audit_mode: "3" },
    { id: "audit-legacy", side: "computer", setting_name: "SubcategoryGuid", path: "AuditSetting/SubcategoryGuid", category: "AuditSetting", value_display: "{0CCE9242-69AE-11D9-BED3-505054503030}" },
    { id: "audit-value", side: "computer", setting_name: "SettingValue", path: "AuditSetting/SettingValue", category: "AuditSetting", value_display: "3" },
    { id: "audit-target", side: "computer", setting_name: "PolicyTarget", path: "AuditSetting/PolicyTarget", category: "AuditSetting", value_display: "System" },
    { id: "audit-mode", side: "computer", setting_name: "AuditSetting", path: "AuditSetting/AuditSetting", category: "AuditSetting", value_display: "Success and Failure" },
    { id: "audit-name", side: "computer", setting_name: "SubcategoryName", path: "AuditSetting/SubcategoryName", category: "AuditSetting", value_display: "Audit Logon" },
    { id: "audit-extension", side: "computer", setting_name: "Extension", path: "AuditSetting/Extension", category: "AuditSetting", value_display: "true" },
    { id: "registry-path", side: "computer", setting_name: "KeyPath", path: "RegistrySetting/KeyPath", category: "RegistrySetting", value_display: "Software\\Example" },
    { id: "registry-value", side: "computer", setting_name: "Value", path: "RegistrySetting/Value", category: "RegistrySetting", value_display: "42" },
    { id: "registry-blocked", side: "computer", setting_name: "Blocked", path: "RegistrySetting/Blocked", category: "RegistrySetting", value_display: "false" },
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
const inventorySnapshot = "10000000-0000-0000-0000-000000000001";
const nextSnapshot = "10000000-0000-0000-0000-000000000002";
let latestSnapshot: string;
let expiredSnapshot: string | undefined;
let inventoryPolicies: typeof policies;

beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("en");
  requests.length = 0;
  latestSnapshot = inventorySnapshot;
  expiredSnapshot = undefined;
  inventoryPolicies = policies;
  window.history.replaceState(null, "", "/app/report/ad.gpo.v2?domain=7");
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = new URL(String(input), window.location.origin);
    requests.push(url);
    const id = url.searchParams.get("policy_id");
    const history = id && url.searchParams.get("tab") === "changes";
    const snapshotList = url.searchParams.has("snapshots");
    const before = url.searchParams.get("before_snapshot");
    const exact = url.searchParams.get("snapshot");
    if (exact && url.searchParams.get("domain") !== "7") return Response.json({ error: "denied" }, { status: 403 });
    if (exact && (exact === expiredSnapshot || ![inventorySnapshot, nextSnapshot].includes(exact))) {
      return Response.json({ error: "missing" }, { status: 404 });
    }
    const observedAt = (exact ?? latestSnapshot) === inventorySnapshot ? older : newer;
    const selected = (exact ?? latestSnapshot) === nextSnapshot ? {
      ...details, settings: [{ ...details.settings[0], value_display: "1200 seconds" }],
      links: [{ ...details.links[0], scope_name: "New Workstations" }],
      versions: [{ ...snapshot, computer_directory_version: 12, computer_sysvol_version: 11 }],
    } : { ...details, versions: [{ ...snapshot, observed_at: older }] };
    const data = { contract_id: "sli.report-result.v2", report_key: "ad.gpo.v2", state: "partial",
      items: id ? policies.filter((row) => row.id === id || row.guid === id) : inventoryPolicies,
      collections: !id ? {} : history ? { changes } :
        snapshotList ? { snapshots: id === "linked" ? snapshots : snapshots.slice(0, 1) } :
          before ? { snapshot_comparison: before === "snapshot-2" ? [] : comparison } : selected,
      has_more: false, next_cursor: null, series: {}, window: {}, metrics: [], filter_options: {},
      coverage: { snapshot_id: exact ?? latestSnapshot, domain_id: 7, observed_at_utc: observedAt, policy_history_state: history ? "ok" : undefined },
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

function openAddress(address: string) {
  cleanup();
  window.history.replaceState(null, "", address);
  return renderReport();
}

function openDetails(id = "linked", tab = "settings", selected?: string) {
  const params = new URLSearchParams({ policy_id: id, domain: "7", snapshot: inventorySnapshot, detail_tab: tab });
  if (selected) params.set("setting", selected);
  return openAddress("/app/report/ad.gpo.v2?" + params);
}

it.each([
  ["en", "Audit Logon", "Success and failure", "Advanced Audit Policy Configuration"],
  ["ru", "Аудит входа в систему", "Успех и отказ", "Расширенная конфигурация политики аудита"],
] as const)("shows readable audit settings for %s", async (locale, name, value, path) => {
  setLocale(locale);
  const { container } = openDetails("linked", "settings", "audit-subcategory");
  const setting = await screen.findByRole("button", { name });
  expect(within(setting.closest("tr")!).getByText(value)).toBeTruthy();
  expect(screen.getByRole("button", { name: locale === "en" ? "Kerberos Authentication Service" : /Служба проверки подлинности Kerberos/ })).toBeTruthy();
  expect(screen.getAllByText(value).length).toBeGreaterThan(0);
  expect(screen.getAllByText(new RegExp(path)).length).toBeGreaterThan(0);
  expect(screen.queryByText(/^(PolicyTarget|SettingValue|SubcategoryGuid|AuditSetting)$/i)).toBeNull();
  expect(screen.queryByText(/SubcategoryName|Extension|RegistrySetting|KeyPath|Blocked|Audit mode|Режим аудита/)).toBeNull();
  expect(within(screen.getByRole("table")).getAllByText(locale === "en" ? "Advanced auditing" : "Расширенный аудит")).toHaveLength(1);
  expect(screen.getByText("Software\\Example")).toBeTruthy();
  expect(screen.getByText("42")).toBeTruthy();
  expect(container.textContent).not.toMatch(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
});

it("links the inventory name by GUID and keeps its filtered list address", async () => {
  renderReport();
  const search = await screen.findByRole("searchbox", { name: "Policy name" });
  fireEvent.change(search, { target: { value: "Updated" } });
  const policy = await screen.findByRole("link", { name: "Updated policy" }, { timeout: 1000 });
  const detail = new URL(policy.getAttribute("href")!, window.location.origin);
  expect(detail.searchParams.get("domain")).toBe("7");
  expect(detail.searchParams.get("policy")).toBe(policies[1].guid);
  expect(detail.searchParams.has("policy_id")).toBe(false);
  expect(detail.searchParams.has("snapshot")).toBe(false);
  const back = new URL(detail.searchParams.get("return_to")!, window.location.origin);
  expect(back.searchParams.get("q")).toBe("Updated");
  expect(requests.filter((request) => request.searchParams.has("policy_id"))).toHaveLength(0);
});

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

it("opens the latest policy by GUID and pins its history request to the returned revision", async () => {
  renderReport();
  const link = await screen.findByRole("link", { name: "Linked policy: 2 links" });
  const address = link.getAttribute("href")!;
  latestSnapshot = nextSnapshot;
  openAddress(address);
  await screen.findByRole("heading", { name: "Linked policy" });
  expect(await screen.findByText("New Workstations")).toBeTruthy();
  expect(screen.queryByText("Workstations")).toBeNull();
  expect(document.querySelector("time")?.dateTime).toBe(newer);
  expect(window.location.search).not.toContain("snapshot=");
  fireEvent.click(screen.getByRole("tab", { name: "Permissions" }));
  expect(screen.getByText("Edit, delete, and modify permissions")).toBeTruthy();
  fireEvent.click(screen.getByRole("tab", { name: "Versions" }));
  expect(within(screen.getByRole("table", { name: "Version history" })).getAllByText("12 / 11").length).toBeGreaterThan(0);
  fireEvent.click(await screen.findByRole("tab", { name: "Changes 1" }));
  expect(screen.getByText("900 seconds →", { exact: false })).toBeTruthy();
  expect(screen.getByText("600 seconds")).toBeTruthy();
  fireEvent.click(screen.getByRole("tab", { name: "Settings" }));
  expect(screen.getByText("1200 seconds")).toBeTruthy();
  expect(screen.queryByText("600 seconds")).toBeNull();
  expect(screen.queryByRole("table", { name: "Group Policies" })).toBeNull();
  const historyRequests = requests.filter((url) => url.searchParams.has("snapshot"));
  expect(historyRequests).toHaveLength(1);
  expect(historyRequests[0].searchParams.get("snapshot")).toBe(nextSnapshot);
  const back = screen.getByRole("link", { name: "Back to policies" });
  openAddress(back.getAttribute("href")!);
  expect(await screen.findByRole("link", { name: "Linked policy" })).toBe(document.activeElement);
});

it("finds settings by path and value, expands history inline, and renders host values as text", async () => {
  openDetails("linked", "settings", "timeout");
  const card = await screen.findByRole("tabpanel");
  const search = await within(card).findByRole("searchbox", { name: "Search by name, path, and value" });
  fireEvent.change(search, { target: { value: "Screen lock" } });
  const timeout = within(card).getByRole("button", { name: "Timeout" });
  expect(timeout.getAttribute("aria-expanded")).toBe("true");
  expect(within(card).getByText("Security/Screen lock")).toBeTruthy();
  expect(await within(card).findByText(/was 900 seconds/)).toBeTruthy();
  fireEvent.change(search, { target: { value: "<img" } });
  expect(within(card).getByText("<img src=x>")).toBeTruthy();
  expect(card.querySelector("img")).toBeNull();
  fireEvent.change(search, { target: { value: "" } });
  await chooseOption(within(card).getByLabelText("Section", { selector: "button" }), "Logging");
  expect(within(card).queryByText("Timeout")).toBeNull();
  fireEvent.click(within(card).getByRole("button", { name: "User 1" }));
  expect(within(card).getByRole("button", { name: "Theme" })).toBeTruthy();
  fireEvent.click(within(card).getByRole("button", { name: "Theme" }));
  expect(new URLSearchParams(window.location.search).get("setting")).toBe("theme");
});

it("compares either of two selected dates in the policy card and distinguishes an equal pair", async () => {
  openDetails("linked", "versions");
  const card = within(await screen.findByRole("tabpanel"));
  const before = await card.findByLabelText("Before", { selector: "button" });
  const after = card.getByLabelText("After", { selector: "button" });
  expect(before.textContent).not.toMatch(/snapshot-/);
  const run = card.getByRole("button", { name: "Compare snapshots" });
  await chooseOption(before, "snapshot-1");
  await chooseOption(after, "snapshot-3");
  fireEvent.click(run);
  const result = within(await card.findByRole("table", { name: "Snapshot comparison" }));
  expect(result.getByRole("row", { name: /Timeout.*Changed.*900 seconds.*600 seconds/ })).toBeTruthy();
  expect(result.getByRole("row", { name: /Theme.*Added.*Enabled/ })).toBeTruthy();
  expect(result.getByRole("row", { name: /Wallpaper.*Removed.*<img src=x>/ })).toBeTruthy();
  expect(card.queryByRole("img")).toBeNull();
  const request = requests.find((url) => url.searchParams.has("before_snapshot"))!;
  expect(Object.fromEntries(request.searchParams)).toMatchObject({ policy_id: "linked", domain: "7", before_snapshot: "snapshot-1", after_snapshot: "snapshot-3" });
  await chooseOption(before, "snapshot-2");
  expect(card.queryByRole("table", { name: "Snapshot comparison" })).toBeNull();
  fireEvent.click(run);
  expect(await card.findByText("No differences in visible settings")).toBeTruthy();
});

it("keeps versions visible when a policy has fewer than two comparable snapshots", async () => {
  openDetails("updated", "versions");
  const card = within(await screen.findByRole("tabpanel"));
  expect(await card.findByText("Two snapshots are required for comparison")).toBeTruthy();
  expect(card.getByRole("table", { name: "Version history" })).toBeTruthy();
  expect(card.queryByRole("button", { name: "Compare snapshots" })).toBeNull();
});

it("reports an expired snapshot without loading the current policy or its history", async () => {
  expiredSnapshot = inventorySnapshot;
  latestSnapshot = nextSnapshot;
  openDetails("linked", "links");
  expect(await screen.findByText("Policy data for the selected time is unavailable.")).toBeTruthy();
  expect(screen.getByRole("link", { name: "Back to policies" }).getAttribute("href")).toContain("domain=7");
  expect(requests.filter((url) => url.pathname.endsWith("/data")).map((url) => url.searchParams.get("snapshot"))).toEqual([inventorySnapshot]);
});

it("names the unavailable setting in the selected policy version", async () => {
  openDetails("linked", "settings", "missing-setting");
  expect(await screen.findByText("The selected setting is missing from the policy data for that time.")).toBeTruthy();
  expect(await screen.findByRole("button", { name: "Timeout" })).toBeTruthy();
});

