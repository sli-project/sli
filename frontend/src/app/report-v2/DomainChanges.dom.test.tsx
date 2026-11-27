// @vitest-environment jsdom
import { chooseOption } from "../../../tests/select-option";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import definitions from "../../../../server-dotnet/src/Sli.Server/Reporting/V2/report-definitions.json";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import { localeRuntime, setLocale } from "../../i18n";
import { ReportRenderer } from "./ReportRenderer";

const key = "security.events.chains";
const definition = {
  ...definitions.find((item) => item.key === key),
  filter_options: {
    domain: [{ value: "7", label: "example.test" }],
    change_operation: [{ value: "4728", label: "4728" }],
  },
} as unknown as ReportDefinitionDto;
const windowBounds = { from_utc: "2026-11-21T01:00:00Z", to_utc_exclusive: "2026-11-21T03:00:00Z" };
const groupChange = {
  event_db_id: 30, event_record_id: 112, event_id: 4728, domain_id: 7, time_created_utc: "2026-11-21T02:30:20Z",
  change_text: "Group member added", change: { kind: "member_added" }, outcome_code: "success",
  actor: { name: "operator" }, member: { name: "example.user" }, group: { name: "Administrators" },
  source_host: { hostname: "dc01.example.test" }, channel: "Security",
};
const attributeChange = {
  ...groupChange, event_db_id: 31, event_id: 4738, member: null, group: null, affected_account: { name: "example.user" },
  change_text: "Account changed", change: { kind: "attributes_changed", attributes: { user_principal_name: "<example.user@example.test>" } },
};
const verifiedChange = {
  ...attributeChange, event_db_id: 32,
  change: {
    kind: "attributes_changed", attributes: { user_principal_name: "current@example.test" },
    previous_attributes: { user_principal_name: { value: "previous@example.test", observed_at_utc: windowBounds.from_utc } },
  },
};

beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("en");
  window.history.replaceState(null, "", `/app/report/${key}?period=custom&from=2026-11-21T01:00:00Z&to=2026-11-21T03:00:00Z`);
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

function openReport() {
  const requests: URL[] = [];
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = new URL(String(input), window.location.origin);
    const { searchParams: params } = url;
    let body: ReportDefinitionDto | ReportResultDto = definition;
    if (url.pathname.endsWith("/data")) {
      requests.push(url);
      const individual = params.get("repeat_mode") === "individual";
      const expanded = params.get("batch") === "30";
      const members = [groupChange, { ...groupChange, event_db_id: 29, member: { name: "other.user" } }];
      const groups = individual || expanded ? members : [{ ...groupChange, repeat_count: 2, first_seen_utc: "2026-11-21T02:30:10Z" }];
      const items = params.get("changes_view") === "accounts" ? [attributeChange, verifiedChange]
        : params.get("changes_view") === "groups" || expanded || params.has("group") ? groups : [...groups, attributeChange, verifiedChange];
      body = {
        contract_id: "sli.report-result.v2", report_key: key, state: "ok", items,
        change_counts: { all: 4, accounts: 2, groups: 2, passwords: 0, audit: 0 },
        has_more: false, next_cursor: null, filtered_count: items.length, metrics: [], series: {},
        filter_options: definition.filter_options, coverage: {}, limitations: [], window: windowBounds,
      };
    }
    return new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
  }));
  render(<QueryClientProvider client={new QueryClient()}>
    <ReportRenderer reportKey={key}/>
  </QueryClientProvider>);
  return requests;
}

it("shows server counts and sends the selected tab and operation", async () => {
  const requests = openReport();
  expect(await screen.findByRole("tab", { name: "All changes 4" })).toBeTruthy();
  expect(screen.getByRole("tab", { name: "Groups 2" })).toBeTruthy();
  const table = within(screen.getByRole("table", { name: "Domain changes" }));
  expect(table.getByRole("columnheader", { name: "Operation outcome" })).toBeTruthy();
  expect(table.getAllByTitle("Success").length).toBeGreaterThan(0);
  expect(table.getByRole("columnheader", { name: "Change" })).toBeTruthy();
  expect(table.queryByText(/· 4728/)).toBeNull();
  expect(table.queryByRole("columnheader", { name: "DC" })).toBeNull();
  fireEvent.click(screen.getByText("Columns", { selector: "summary" }));
  fireEvent.click(within(screen.getByRole("group", { name: "Columns" })).getByRole("checkbox", { name: "DC" }));
  expect(table.getByRole("columnheader", { name: "DC" })).toBeTruthy();
  expect(table.getAllByText("dc01.example.test").length).toBeGreaterThan(0);
  fireEvent.click(screen.getByRole("tab", { name: "Accounts 2" }));
  const value = await screen.findByText("<example.user@example.test>");
  expect(value.innerHTML).toContain("&lt;");
  expect(value.textContent).toBe("<example.user@example.test>");
  const verified = await screen.findByText("previous@example.test → current@example.test");
  expect(verified.closest("td")).toBeTruthy();
  expect(requests.at(-1)?.searchParams.get("changes_view")).toBe("accounts");
  await chooseOption(screen.getByLabelText("Operation", { selector: "button" }), "4728");
  await waitFor(() => expect(requests.at(-1)?.searchParams.get("event_id")).toBe("4728"));
  expect(screen.getByLabelText("Operation", { selector: "button" }).textContent).toContain("Member added to global group");
});

it("requests batch members only after expansion and opens their source event and group history", async () => {
  const requests = openReport();
  const batch = await screen.findByRole("button", { name: /Group member added.*×2/ });
  expect(requests.some(({ searchParams }) => searchParams.has("batch"))).toBe(false);
  expect((screen.getByRole("checkbox", { name: "Collapse repeats" }) as HTMLInputElement).checked).toBe(true);
  fireEvent.click(batch);
  const child = await screen.findByText("other.user");
  expect(requests.at(-1)?.searchParams.get("batch")).toBe("30");
  expect(child.closest("table")?.querySelector("caption")?.textContent).toBe("Changes in this group");
  fireEvent.click(child.closest("tr")!);
  const details = screen.getByRole("complementary", { name: "Group member added" });
  const link = within(details).getByRole("link", { name: "Open event" });
  const href = new URL(link.getAttribute("href")!, window.location.origin);
  expect(href.pathname).toBe("/app/events/29");
  expect(href.searchParams.get("time_from")).toBe(windowBounds.from_utc);
  fireEvent.click(within(details).getByRole("tab", { name: "Source event" }));
  expect(within(details).getByText("Security")).toBeTruthy();
  expect(within(details).getByText("4728")).toBeTruthy();
  fireEvent.click(within(details).getByRole("button", { name: /History for Administrators/ }));
  await waitFor(() => expect(requests.at(-1)?.searchParams.get("group")).toBe("Administrators"));
  expect(requests.at(-1)?.searchParams.get("domain")).toBe("7");
  fireEvent.click(screen.getByRole("checkbox", { name: "Collapse repeats" }));
  await waitFor(() => expect(requests.at(-1)?.searchParams.get("repeat_mode")).toBe("individual"));
});
