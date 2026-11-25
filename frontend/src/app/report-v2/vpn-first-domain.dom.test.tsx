// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, ApiResponseError, type SetupStatus, type V4Access } from "../../api/client";
import type { ReportDefinitionDto } from "../../api/report-v2-types";
import definitions from "../../../../server-dotnet/src/Sli.Server/Reporting/V2/report-definitions.json";
import { OverlayProvider } from "../../design-system";
import { t } from "../../i18n";
import * as app from "../App";
import { SetupPage } from "../admin/setup";
import { ReportWorkspacePage } from "../report-workspace";

vi.mock("@tanstack/react-router", async importOriginal => ({
  ...await importOriginal<typeof import("@tanstack/react-router")>(),
  useLocation: () => ({ href: window.location.href, searchStr: window.location.search, search: {} }),
  useNavigate: () => vi.fn(),
}));

const REPORT = "vpn.connections";
const date = "2026-11-25T00:00:00Z";
const route = definitions.find(item => item.key === REPORT)! as unknown as ReportDefinitionDto;
const declaration: ReportDefinitionDto = {
  ...route, filter_options: { domain: [] }, access: { allowed: true }, default_domain_id: null,
  default_domain_state: "unknown", plugin: { plugin_id: "sli.remote-access", state: "enabled", read_only: false },
};

const clean: SetupStatus = {
  api_version: "v1", generated_at_utc: date, read_only: true,
  steps: [{ id: "domains", title: "Domains", state: "todo", summary: "No domains" }],
  report_domain: { key: "reports.domain_fqdn", value: "", source: "not_configured" },
  domains: [], domain_controllers: [], domain_controller_source: "none", sources: [], collection: null,
  agent_collection: { state: "unknown", checked_at_utc: date, active_agents: 0, current_agents: 0, items: [] },
};

function access(overrides: Partial<V4Access> = {}): V4Access {
  return {
    api_version: "v4", evaluated_at_utc: date, platform_owner: true, preview: false,
    subject: { type: "user", username: "vpn-test", coarse_role: "admin" },
    groups: [], packages: [], package_explain: [], capabilities: ["access.manage"], capability_explain: {},
    reports: [{ report_key: "vpn.audit", allowed: true } as V4Access["reports"][number]],
    allowed_report_count: 1, navigation: [], explicit_denies: { packages: [], capabilities: [], reports: [] },
    ...overrides,
  };
}

function openReport(search = "") {
  window.history.replaceState(null, "", "/app/report/" + REPORT + search);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrap = (page: ReactNode) => <QueryClientProvider client={client}><OverlayProvider>{page}</OverlayProvider></QueryClientProvider>;
  const view = render(wrap(<ReportWorkspacePage reportKey={REPORT}/>));
  return { showSetup: () => view.rerender(wrap(<SetupPage/>)) };
}

const action = () => screen.queryByRole("link", { name: t("setup.domain.add") });
const required = () => screen.findByText(t("reports.renderer.required_conditions"));
const badge = () => screen.queryByText(t("domain.archive.noDefault"));

beforeEach(() => {
  vi.spyOn(app, "useAccessStatus").mockReturnValue("получены");
  vi.spyOn(app, "useEffectiveAccess").mockReturnValue(access());
  vi.spyOn(api, "reportsV2Catalog").mockResolvedValue({ contract_id: "sli.report-catalog.v2", items: [] });
  vi.spyOn(api, "reportV2Definition").mockResolvedValue(declaration);
  vi.spyOn(api, "setupStatus").mockResolvedValue(clean);
  vi.spyOn(api, "reportV2Data").mockRejectedValue(new ApiResponseError(403, "domain_scope_denied"));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); window.history.replaceState(null, "", "/"); });

describe("VPN first domain", () => {
  it("offers one action from the VPN workspace to the existing domain form", async () => {
    const view = openReport("?nav_view=connections");
    const link = await screen.findByRole("link", { name: t("setup.domain.add") });
    const target = link.getAttribute("href");
    expect(target).toBe("/app/setup#setup-domains");
    expect(screen.getAllByRole("link")).toEqual([link]);
    expect(screen.queryByText(t("reports.renderer.required_conditions"))).toBeNull();
    expect(badge()).toBeNull();
    expect(api.reportV2Data).not.toHaveBeenCalled();

    const domain = { fqdn: "vpn.example.test", netbios_name: null, server_count: 0 };
    const register = vi.spyOn(api, "addSetupDomain").mockImplementation(async () => {
      vi.mocked(api.setupStatus).mockResolvedValue({ ...clean, domains: [domain] });
      return { item: domain };
    });
    window.history.replaceState(null, "", target!);
    view.showSetup();
    const field = await screen.findByLabelText(t("setup.domain.labelFqdn"));
    expect(field.closest("#setup-domains")).toBeTruthy();
    fireEvent.change(field, { target: { value: domain.fqdn } });
    fireEvent.click(screen.getByRole("button", { name: t("setup.domain.add") }));
    await screen.findByText(t("setup.domain.added"));
    expect(register).toHaveBeenCalledWith({ fqdn: domain.fqdn });
  });

  it.each(["?scope=all", "?domain=7&period=custom", "?domain_id=7&period=custom", "?q=synthetic"])(
    "preserves the existing required-fields state with %s", async search => {
      openReport(search);
      expect(await required()).toBeTruthy();
      expect(action()).toBeNull();
      expect(api.setupStatus).not.toHaveBeenCalled();
    },
  );

  it.each(["disabled", "unknown"] as const)("keeps the existing report state for plugin status %s", async state => {
    vi.mocked(api.reportV2Definition).mockResolvedValue({
      ...declaration, plugin: { plugin_id: "sli.remote-access", state, read_only: true },
    });
    openReport();
    expect(await required()).toBeTruthy();
    expect(badge()).toBeTruthy();
    expect(action()).toBeNull();
    expect(api.setupStatus).not.toHaveBeenCalled();
  });

  it("preserves the backend denial", async () => {
    vi.mocked(api.reportV2Definition).mockRejectedValue(new ApiResponseError(403, "report_access_denied"));
    openReport();
    expect(await screen.findByRole("link", { name: t("reports.access.own_rights") })).toBeTruthy();
    expect(action()).toBeNull();
    expect(api.setupStatus).not.toHaveBeenCalled();
  });

  it("does not offer setup if the initial view denies access", async () => {
    vi.mocked(api.reportV2Definition).mockResolvedValue({
      ...declaration, views: [{ ...declaration.views[0], access: { allowed: false } }, ...declaration.views.slice(1)],
    });
    openReport();
    expect(await screen.findByRole("link", { name: t("reports.access.own_rights") })).toBeTruthy();
    expect(action()).toBeNull();
    expect(api.setupStatus).not.toHaveBeenCalled();
  });

  it("does not offer setup without confirmed configuration", async () => {
    vi.mocked(api.setupStatus).mockRejectedValue(new ApiResponseError(503, "setup_unavailable"));
    openReport();
    expect(await required()).toBeTruthy();
    expect(badge()).toBeTruthy();
    expect(action()).toBeNull();
  });

  it.each([access({ platform_owner: false }), access({ capabilities: [] }), access({ preview: true })])(
    "preserves the report when the current user cannot configure the first domain", async restricted => {
      vi.mocked(app.useEffectiveAccess).mockReturnValue(restricted);
      openReport();
      expect(await required()).toBeTruthy();
      expect(action()).toBeNull();
      expect(api.setupStatus).not.toHaveBeenCalled();
    },
  );

  it("does not offer setup for an empty report when a domain is already registered", async () => {
    vi.mocked(api.setupStatus).mockResolvedValue({
      ...clean, domains: [{ fqdn: "existing.example.test", netbios_name: null, server_count: 0 }],
    });
    openReport();
    expect(await required()).toBeTruthy();
    expect(action()).toBeNull();
  });

  it("loads the report with a normal selected domain", async () => {
    vi.mocked(api.reportV2Definition).mockResolvedValue({
      ...declaration, default_domain_state: "available", default_domain_id: 7,
      filter_options: { domain: [{ value: "7", label: "vpn.example.test" }] },
    });
    vi.mocked(api.reportV2Data).mockResolvedValue({
      report_key: REPORT, contract_id: "sli.report-result.v2", state: "empty",
      items: [], has_more: false, next_cursor: null, filtered_count: 0,
      metrics: [], series: {}, coverage: {}, filter_options: {}, limitations: [], window: {},
    });
    openReport("?domain=7");
    await waitFor(() => expect(vi.mocked(api.reportV2Data).mock.calls.some(([key, params]) =>
      key === REPORT && params.get("domain") === "7")).toBe(true));
    expect(action()).toBeNull();
    expect(api.setupStatus).not.toHaveBeenCalled();
  });
});
