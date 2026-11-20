// @vitest-environment jsdom
import { createElement } from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import type { PluginHostApi } from "./contract";
import { createPlugin } from "../../plugins/remote-access/entry";

const state = vi.hoisted(() => ({ status: "получены", access: {
  subject: { type: "user", id: 1 }, evaluated_at_utc: "fixture-revision", capabilities: ["reports.catalog"],
} }));
vi.mock("../app/App", () => ({ useAccessStatus: () => state.status, useEffectiveAccess: () => state.access }));
vi.mock("@tanstack/react-router", () => ({ useNavigate: () => vi.fn() }));
vi.mock("../app/report-v2/ReportRenderer", () => ({ ReportRenderer: ({ reportKey }: { reportKey: string }) => <p>Existing {reportKey}</p> }));
vi.mock("./PluginHost", () => ({ PluginHost: ({ pluginId, Page }: { pluginId: string; Page?: () => ReturnType<typeof createElement> }) => <div data-testid="plugin-host">{pluginId}{Page ? <Page/> : null}</div> }));
import { InstalledPluginPage, PluginReportPage } from "./routes";

afterEach(() => { cleanup(); state.status = "получены"; });

it("preserves the VPN page when the pilot flag is off", () => {
  render(<PluginReportPage reportKey="vpn.accounts" pilotEnabled={false}/>);
  expect(screen.getByText("Existing vpn.accounts")).toBeTruthy();
  expect(screen.queryByTestId("plugin-host")).toBeNull();
});

it("wraps the same VPN page with the plugin host when enabled", () => {
  render(<PluginReportPage reportKey="vpn.accounts" pilotEnabled/>);
  expect(screen.getByTestId("plugin-host").textContent).toContain("sli.remote-access");
  expect(screen.getByText("Existing vpn.accounts")).toBeTruthy();
});

it("leaves other reports on their existing renderer", () => {
  render(<PluginReportPage reportKey="vpn.connections" pilotEnabled/>);
  expect(screen.getByText("Existing vpn.connections")).toBeTruthy();
  expect(screen.queryByTestId("plugin-host")).toBeNull();
});

it.each([false, true])("keeps bundled AD pages independent of external plugin JS (pilot=%s)", (pilotEnabled) => {
  render(<PluginReportPage reportKey="ad.users.v2" pilotEnabled={pilotEnabled}/>);
  expect(screen.getByText("Existing ad.users.v2")).toBeTruthy();
  expect(screen.queryByTestId("plugin-host")).toBeNull();
});

it.each([
  "ad.infrastructure", "ad.users.v2", "ad.computers.v6", "ad.computer-logons", "ad.new-logon-pairs",
  "ad.privileged", "ad.users", "ad.computers", "ad.computers.v2", "ad.computers.v4", "ad.computers.v5",
])("approves only the specific bundled AD report route %s", (reportKey) => {
  render(<InstalledPluginPage pluginId="sli.ad" route={`/report/${reportKey}`}/>);
  expect(screen.getByText(`Existing ${reportKey}`)).toBeTruthy();
  expect(screen.queryByTestId("plugin-host")).toBeNull();
});

it.each(["/report/ad.unreviewed", "/report/ad.users.v2/extra", "/report/ad.users.v2?domain=1", "/extensions/sli.ad/users", "/report/ad.gpo.v2"])
  ("does not grant an AD page adapter to %s", (route) => {
    render(<InstalledPluginPage pluginId="sli.ad" route={route}/>);
    expect(screen.getByTestId("plugin-host").textContent).toBe("sli.ad");
    expect(screen.queryByText(/^Existing /)).toBeNull();
  });

it("does not supply AD pages to another plugin", () => {
  render(<InstalledPluginPage pluginId="sli.gpo" route="/report/ad.users.v2"/>);
  expect(screen.queryByText("Existing ad.users.v2")).toBeNull();
});

it("does not mount the pilot when access evaluation failed", () => {
  state.status = "отказ";
  render(<PluginReportPage reportKey="vpn.accounts" pilotEnabled/>);
  expect(screen.getByRole("alert").getAttribute("data-state")).toBe("unavailable");
  expect(screen.queryByTestId("plugin-host")).toBeNull();
});

it("the independent pilot uses only the approved Page and owns its own lifecycle", () => {
  const renderNode = vi.fn();
  const Page = () => createElement("p", null, "Fixture VPN page");
  const container = document.createElement("div");
  const api = { ui_api: "sli.plugin-ui.v1", Page, react: { createElement }, render: renderNode } as unknown as PluginHostApi;
  const first = createPlugin();
  const second = createPlugin();
  first.mount(container, api);
  second.mount(container, api);
  expect(renderNode.mock.calls[0][1].type).toBe(Page);
  first.unmount();
  first.unmount();
  expect(renderNode).toHaveBeenCalledTimes(3);
  second.unmount();
  expect(renderNode).toHaveBeenCalledTimes(4);
  expect(renderNode).toHaveBeenLastCalledWith(container, null);
});
