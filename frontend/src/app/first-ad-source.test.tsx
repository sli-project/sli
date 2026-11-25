// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, ApiResponseError, type SetupStatus } from "../api/client";
import type { ReportDefinitionDto, ReportResultDto } from "../api/report-v2-types";
import definitions from "../../../server-dotnet/src/Sli.Server/Reporting/V2/report-definitions.json";
import { OverlayProvider } from "../design-system";
import { t } from "../i18n";
import * as app from "./App";
import { HomePage } from "./home";
import { ReportRenderer } from "./report-v2/ReportRenderer";

vi.mock("@tanstack/react-router", async importOriginal => ({
  ...await importOriginal<typeof import("@tanstack/react-router")>(),
  useLocation: () => ({ searchStr: "" }),
  useNavigate: () => vi.fn(),
}));

const checkedAt = "2026-11-25T01:00:00Z";
const emptySetup: SetupStatus = {
  api_version: "v1", generated_at_utc: checkedAt, read_only: true,
  steps: [{ id: "domains", title: "Domains", state: "todo", summary: "No domains" }],
  report_domain: { key: "reports.domain_fqdn", source: "not_configured", value: "" },
  domains: [], domain_controllers: [], domain_controller_source: "none", sources: [],
  agent_collection: { state: "unknown", checked_at_utc: checkedAt, active_agents: 0, current_agents: 0, items: [] },
  collection: null,
};

function ownerAccess(owner: boolean) {
  vi.spyOn(app, "useEffectiveAccess").mockReturnValue({
    api_version: "v4", evaluated_at_utc: checkedAt, platform_owner: owner, preview: false,
    subject: { type: "user", username: "scope-test", coarse_role: owner ? "admin" : "viewer" },
    groups: [], packages: [], package_explain: [], capabilities: ["workspace.view"], capability_explain: {},
    reports: [], allowed_report_count: 0, navigation: [],
    explicit_denies: { packages: [], capabilities: [], reports: [] },
  });
}

function show(page: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}>{page}</QueryClientProvider>);
}

function definition(key: string): ReportDefinitionDto {
  return {
    key, section: "investigation", title: "Synthetic report", description: "Scope test",
    archetype: "investigation-evidence", params: [{ key: "domain", label: "Domain", kind: "domain" }],
    columns: [], views: [{ kind: "table", key: "table" }], row_key: "id", detail: "fields",
    export: false, limits: { default: 50, max: 100 }, presets: [], row_links: [], filter_options: {},
  };
}

beforeEach(() => {
  ownerAccess(true);
  vi.spyOn(app, "useAccessStatus").mockReturnValue("получены");
  vi.spyOn(api, "setupStatus").mockResolvedValue(emptySetup);
  vi.spyOn(api, "homePeriod").mockResolvedValue({
    domains: [], domain_id: null, from: checkedAt, to: checkedAt, updated_at: checkedAt,
    problems: null, controllers: null, activity: null, changes: null,
  });
  vi.spyOn(api, "reportV2Definition").mockImplementation(async key => definition(key));
  vi.spyOn(api, "reportV2Data").mockRejectedValue(new ApiResponseError(403, "domain_scope_denied"));
  vi.spyOn(api, "v4Reports").mockResolvedValue({
    api_version: "v4", state: "available", allowed_count: 0, total_count: 0, items: [], explain_contract: "",
  });
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("offers the owner a single path to add the first agent on the empty Home page", async () => {
  show(<HomePage/>);
  const action = await screen.findByRole("link", { name: t("agents.addComputer") });
  expect(action.getAttribute("href")).toBe("/app/agents?register=1");
  expect(screen.getAllByRole("link")).toEqual([action]);
});

it.each(["security.events.chains", "ad.infrastructure", "ad.users.v2", "ad.computers.v6"])(
  "offers first enrollment to the owner on %s when the setup is empty", async reportKey => {
    show(<ReportRenderer reportKey={reportKey} initialSearch=""/>);
    const action = await screen.findByRole("link", { name: t("agents.addComputer") });
    expect(action.getAttribute("href")).toBe("/app/agents?register=1");
    expect(screen.queryByRole("link", { name: t("reports.access.own_rights") })).toBeNull();
    expect(api.reportV2Data).not.toHaveBeenCalled();
  },
);

it("keeps an actual report denial when a limited user has no accessible domain", async () => {
  ownerAccess(false);
  show(<ReportRenderer reportKey="security.events.chains" initialSearch=""/>);
  expect(await screen.findByRole("link", { name: t("reports.access.own_rights") })).toBeTruthy();
  expect(screen.queryByRole("link", { name: t("agents.addComputer") })).toBeNull();
  expect(api.setupStatus).not.toHaveBeenCalled();
});

it.each(["domain=22", "domain_id=22"])("preserves the denial when the owner requests %s", async search => {
  show(<ReportRenderer reportKey="security.events.chains" initialSearch={search}/>);
  expect(await screen.findByRole("link", { name: t("reports.access.own_rights") })).toBeTruthy();
  expect(screen.queryByRole("link", { name: t("agents.addComputer") })).toBeNull();
  expect(api.setupStatus).not.toHaveBeenCalled();
  expect(vi.mocked(api.reportV2Data).mock.calls.some(([, params]) =>
    (params.get("domain") ?? params.get("domain_id")) === "22")).toBe(true);
});

it.each(["domain", "domain_id"])("keeps a direct %s on the AD state report when its declaration hides the selector", async selector => {
  const entry = "/app/report/ad.infrastructure?" + selector + "=999999";
  const previous = window.location.pathname + window.location.search + window.location.hash;
  window.history.replaceState(null, "", entry);
  vi.mocked(api.reportV2Definition).mockResolvedValue({
    ...definition("ad.infrastructure"), params: [], default_domain_state: "unknown",
    views: [{ kind: "table", key: "controls", access: { allowed: false } }],
  });
  try {
    show(<ReportRenderer reportKey="ad.infrastructure"/>);
    expect(await screen.findByRole("link", { name: t("reports.access.own_rights") })).toBeTruthy();
    expect(new URLSearchParams(window.location.search).get(selector)).toBe("999999");
    expect(screen.queryByRole("link", { name: t("agents.addComputer") })).toBeNull();
    expect(api.setupStatus).not.toHaveBeenCalled();
  } finally {
    cleanup();
    window.history.replaceState(null, "", previous);
  }
});

it.each([
  ["ad.users.v2", "all"],
  ["ad.computers.v6", "computers"],
])("retains both direct selectors when switching denied %s tabs", async (reportKey, initialTab) => {
  const previous = window.location.pathname + window.location.search + window.location.hash;
  window.history.replaceState(null, "", "/app/report/" + reportKey + "?domain=7&domain_id=8");
  vi.mocked(api.reportV2Definition).mockResolvedValue({
    ...definition(reportKey), params: [], default_domain_state: "unknown",
    views: [
      { kind: "table", key: initialTab, access: { allowed: false } },
      { kind: "table", key: "changes", access: { allowed: false } },
    ],
  });
  try {
    show(<ReportRenderer reportKey={reportKey}/>);
    expect(await screen.findByRole("link", { name: t("reports.access.own_rights") })).toBeTruthy();
    fireEvent.click(screen.getAllByRole("tab")[1]);
    await waitFor(() => {
      const query = new URLSearchParams(window.location.search);
      expect(query.get("tab")).toBe("changes");
      expect(query.get("domain")).toBe("7");
      expect(query.get("domain_id")).toBe("8");
    });
    expect(screen.queryByRole("link", { name: t("agents.addComputer") })).toBeNull();
  } finally {
    cleanup();
    window.history.replaceState(null, "", previous);
  }
});

it("replaces the old domain alias after choosing a different domain in the computers filter", async () => {
  const previous = window.location.pathname + window.location.search + window.location.hash;
  window.history.replaceState(null, "", "/app/report/ad.computers.v6?domain=7&domain_id=7");
  vi.mocked(api.reportV2Definition).mockResolvedValue({
    ...definition("ad.computers.v6"),
    params: [
      { key: "domain", label: "Domain", kind: "domain", options: [{ value: "7", label: "First" }, { value: "8", label: "Second" }] },
      { key: "domain_id", label: "Domain ID", kind: "domain", hidden: true },
    ],
    views: [{ kind: "table", key: "computers" }],
  });
  vi.mocked(api.reportV2Data).mockResolvedValue({
    contract_id: "sli.report-result.v2", report_key: "ad.computers.v6", state: "empty", items: [],
    has_more: false, next_cursor: null, filtered_count: 0, metrics: [], series: {},
    coverage: {}, filter_options: {}, limitations: [], window: {},
  });
  try {
    show(<ReportRenderer reportKey="ad.computers.v6"/>);
    const selector = await screen.findByRole("combobox", { name: "Domain" });
    fireEvent.change(selector, { target: { value: "8" } });
    await waitFor(() => {
      const query = new URLSearchParams(window.location.search);
      expect(query.get("domain")).toBe("8");
      expect(query.has("domain_id")).toBe(false);
      expect(vi.mocked(api.reportV2Data).mock.calls.some(([, params]) =>
        params.get("domain") === "8" && !params.has("domain_id"))).toBe(true);
    });
  } finally {
    cleanup();
    window.history.replaceState(null, "", previous);
  }
});

it("does not show enrollment when the global setup has a registered domain", async () => {
  vi.mocked(api.setupStatus).mockResolvedValue({
    ...emptySetup, domains: [{ fqdn: "existing.example.test", netbios_name: null, server_count: 0 }],
  });
  show(<ReportRenderer reportKey="security.events.chains" initialSearch=""/>);
  expect(await screen.findByRole("link", { name: t("reports.access.own_rights") })).toBeTruthy();
  expect(api.setupStatus).toHaveBeenCalled();
  expect(screen.queryByRole("link", { name: t("agents.addComputer") })).toBeNull();
});

it("does not treat an unavailable domain read as an empty setup", async () => {
  vi.mocked(api.setupStatus).mockResolvedValue({
    ...emptySetup, steps: [{ ...emptySetup.steps[0], state: "unavailable" }],
  });
  show(<ReportRenderer reportKey="security.events.chains" initialSearch=""/>);
  expect(await screen.findByRole("link", { name: t("reports.access.own_rights") })).toBeTruthy();
  expect(api.setupStatus).toHaveBeenCalled();
  expect(screen.queryByRole("link", { name: t("agents.addComputer") })).toBeNull();
});

const sourceReportKeys = ["events.journal", "ad.gpo.v2", "security.problems"] as const;
type SourceReportKey = typeof sourceReportKeys[number];

function showEmptySourceReport(key: SourceReportKey, options: { search?: string; denied?: boolean } = {}) {
  const report = definitions.find(item => item.key === key);
  expect(report).toBeDefined();
  vi.mocked(api.reportV2Definition).mockResolvedValue({ ...report, filter_options: {} } as unknown as ReportDefinitionDto);
  if (!options.denied) {
    const result: ReportResultDto = {
      contract_id: "sli.report-result.v2", report_key: key, state: "empty", items: [],
      has_more: false, next_cursor: null, filtered_count: 0, metrics: [], series: {},
      coverage: {}, filter_options: {}, limitations: [], window: {},
    };
    vi.mocked(api.reportV2Data).mockResolvedValue(result);
  }
  show(<OverlayProvider><ReportRenderer reportKey={key} initialSearch={options.search ?? ""}/></OverlayProvider>);
}

function settledEmptySourceReport(key: SourceReportKey) {
  if (key === "events.journal") return screen.findByText(t("reports.v2.events.journal.empty"));
  if (key === "security.problems") return screen.findByText(t("problems.queue.empty"));
  return screen.findByRole("table");
}

it.each(sourceReportKeys)("offers one enrollment action from the unfiltered %s for a first source", async key => {
  showEmptySourceReport(key);
  const action = await screen.findByRole("link", { name: t("agents.addComputer") });
  expect(action.getAttribute("href")).toBe("/app/agents?register=1");
  expect(screen.getAllByRole("link", { name: t("agents.addComputer") })).toEqual([action]);
});

it.each(sourceReportKeys)("keeps a true data denial on %s", async key => {
  showEmptySourceReport(key, { denied: true });
  expect(await screen.findByRole("link", { name: t("reports.access.own_rights") })).toBeTruthy();
  expect(screen.queryByRole("link", { name: t("agents.addComputer") })).toBeNull();
  expect(api.setupStatus).not.toHaveBeenCalled();
});

it.each(sourceReportKeys)("retains a settled empty result on %s with a configured domain", async key => {
  vi.mocked(api.setupStatus).mockResolvedValue({
    ...emptySetup, domains: [{ fqdn: "configured.example.test", netbios_name: null, server_count: 0 }],
  });
  showEmptySourceReport(key);
  await settledEmptySourceReport(key);
  await waitFor(() => expect(api.setupStatus).toHaveBeenCalled());
  expect(screen.queryByRole("link", { name: t("agents.addComputer") })).toBeNull();
});

it.each(sourceReportKeys.flatMap(key => ["domain_id=7", "scope=all", "q=synthetic"].map(search => [key, search] as const)))(
  "keeps the existing empty %s with %s", async (key, search) => {
    showEmptySourceReport(key, { search });
    await settledEmptySourceReport(key);
    expect(api.setupStatus).not.toHaveBeenCalled();
    expect(screen.queryByRole("link", { name: t("agents.addComputer") })).toBeNull();
  },
);

it("keeps the empty journal for a viewer without enrollment rights", async () => {
  ownerAccess(false);
  showEmptySourceReport("events.journal");
  await settledEmptySourceReport("events.journal");
  expect(api.setupStatus).not.toHaveBeenCalled();
  expect(screen.queryByRole("link", { name: t("agents.addComputer") })).toBeNull();
});
