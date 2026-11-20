// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import type { AgentItem } from "../../api/client";
import { t } from "../../i18n";
import { AgentModuleControls } from "./agent-policy-controls";
import domainRequest from "../../test-fixtures/password_detection_domain_ui_request.json";

const agent: AgentItem = {
  id: "00000000-0000-4000-8000-000000000001", host_id: "00000000-0000-4000-8000-000000000002",
  status: "active", last_seen: null, policy_revision: 7, applied_policy_revision: 6,
  assigned_modules: [], certificates: [], rights_probe: {},
};
function mount(module_id = "sli.ad-snapshot", config: Record<string, unknown> = {}, enabled = true, busy = false, status: AgentItem["status"] = "active") {
  const change = vi.fn();
  render(<AgentModuleControls agent={{ ...agent, status }} module={{ module_id, enabled, config }} busy={busy} change={change}/>);
  fireEvent.click(screen.getByText(t("agents.snapshotSchedule")));
  return change;
}
const submit = () => fireEvent.submit(screen.getByRole("button", { name: t("agents.saveSchedule") }).closest("form")!);
afterEach(cleanup);

it("saves DC initial depth without changing its source or filters", () => {
  const change = vi.fn();
  const config = { source_name: "fixture-source", connect_address: "localhost", allow_event_ids: [4624] };
  render(<AgentModuleControls agent={agent} module={{ module_id: "sli.windows.ad-dc", enabled: true, config }} busy={false} change={change}/>);
  fireEvent.click(screen.getByText(t("agents.channelSettings")));
  expect((screen.getByLabelText(t("agents.initialReadHours")) as HTMLInputElement).value).toBe("24");
  fireEvent.change(screen.getByLabelText(t("agents.initialReadHours")), { target: { value: "0" } });
  fireEvent.submit(screen.getByRole("button", { name: t("agents.saveInitialRead") }).closest("form")!);
  expect(change).toHaveBeenCalledWith("modules", { agent_id: agent.id, module_id: "sli.windows.ad-dc", enabled: true,
    expected_revision: 7, config: { ...config, initial_read_hours: 0 } });
});

it("saves the explicit all-history initial mode", () => {
  const change = vi.fn();
  render(<AgentModuleControls agent={agent} module={{ module_id: "sli.windows.ad-dc", enabled: true, config: {} }} busy={false} change={change}/>);
  fireEvent.click(screen.getByText(t("agents.channelSettings")));
  fireEvent.click(screen.getByLabelText(t("agents.initialReadAll")));
  fireEvent.submit(screen.getByRole("button", { name: t("agents.saveInitialRead") }).closest("form")!);
  expect(change).toHaveBeenCalledWith("modules", expect.objectContaining({ config: { initial_read_hours: "all" } }));
});

it("issues a separate history command with frozen bounds and fresh channel generations", () => {
  const change = vi.fn();
  const config = { source_name: "fixture-source", connect_address: "localhost", allow_event_ids: [4624], channels: { System: false } };
  render(<AgentModuleControls agent={agent} module={{ module_id: "sli.windows.ad-dc", enabled: true, config }} busy={false} change={change}/>);
  fireEvent.click(screen.getByText(t("agents.channelSettings")));
  fireEvent.click(screen.getByRole("button", { name: t("agents.backfillDc") }));
  expect(change).toHaveBeenCalledOnce();
  const [kind, body] = change.mock.calls[0];
  expect(kind).toBe("modules");
  expect(body).toEqual({ agent_id: agent.id, module_id: "sli.windows.ad-dc-history", enabled: true, expected_revision: 7,
    config: { ...config, initial_read_hours: "all", batch_size: 4, history_before_utc: expect.any(String),
      channel_generations: { Security: expect.any(String), System: expect.any(String), "Directory Service": expect.any(String) } } });
  expect(Number.isNaN(Date.parse(body.config.history_before_utc))).toBe(false);
  expect(new Set(Object.values(body.config.channel_generations)).size).toBe(1);
});

it("disables DC history commands and depth edits while busy", () => {
  render(<AgentModuleControls agent={agent} module={{ module_id: "sli.windows.ad-dc", enabled: true, config: {} }} busy={true} change={vi.fn()}/>);
  fireEvent.click(screen.getByText(t("agents.channelSettings")));
  expect((screen.getByRole("button", { name: t("agents.backfillDc") }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByRole("button", { name: t("agents.saveInitialRead") }).closest("fieldset")?.disabled).toBe(true);
});

it.each(["sli.ad-snapshot", "sli.gpo-snapshot"])("uses the supported default for %s without discarding its binding", (module_id) => {
  const config = { source_instance_id: agent.host_id, scope: "fixture-scope", capture_seconds: 300 };
  const change = mount(module_id, config);
  expect((screen.getByLabelText(t("agents.scheduleTimezone")) as HTMLInputElement).value).toBe("Asia/Novosibirsk");
  expect((screen.getByLabelText(t("agents.scheduleHours")) as HTMLInputElement).value).toBe("6, 18");
  submit();
  expect(change).toHaveBeenCalledWith("modules", { agent_id: agent.id, module_id, enabled: true, expected_revision: 7,
    config: { ...config, schedule: { timezone: "Asia/Novosibirsk", hours: [6, 18] } } });
});

it("edits a disabled module's schedule, normalizes hours and preserves its disabled state", () => {
  const config = { schedule: { timezone: "UTC", hours: [0] }, expensive_flags: { dns: true } };
  const change = mount("sli.gpo-snapshot", config, false);
  expect((screen.getByLabelText(t("agents.scheduleTimezone")) as HTMLInputElement).value).toBe("UTC");
  expect((screen.getByLabelText(t("agents.scheduleHours")) as HTMLInputElement).value).toBe("0");
  fireEvent.change(screen.getByLabelText(t("agents.scheduleTimezone")), { target: { value: " Asia/Kathmandu " } });
  fireEvent.change(screen.getByLabelText(t("agents.scheduleHours")), { target: { value: "23, 0, 8, 8" } });
  submit();
  expect(change).toHaveBeenCalledWith("modules", { agent_id: agent.id, module_id: "sli.gpo-snapshot", enabled: false, expected_revision: 7,
    config: { ...config, schedule: { timezone: "Asia/Kathmandu", hours: [0, 8, 23] } } });
});

it.each(["", "24", "-1", "1.5", "1,,2", "false"])("rejects invalid hours %s before sending a policy", (hours) => {
  const change = mount();
  fireEvent.change(screen.getByLabelText(t("agents.scheduleHours")), { target: { value: hours } });
  submit();
  expect(change).not.toHaveBeenCalled();
  expect(screen.getByRole("alert").textContent).toBe(t("agents.invalidSchedule"));
});

it("rejects an unknown time zone and clears the error after correction", () => {
  const change = mount();
  fireEvent.change(screen.getByLabelText(t("agents.scheduleTimezone")), { target: { value: "invalid/timezone" } });
  submit();
  expect(change).not.toHaveBeenCalled();
  expect(screen.getByRole("alert")).toBeTruthy();
  fireEvent.change(screen.getByLabelText(t("agents.scheduleTimezone")), { target: { value: "UTC" } });
  submit();
  expect(change).toHaveBeenCalledOnce();
  expect(screen.queryByRole("alert")).toBeNull();
});

it.each([{ busy: true, status: "active" as const }, { busy: false, status: "disabled" as const }])("disables schedule changes for $status when busy=$busy", ({ busy, status }) => {
  mount("sli.ad-snapshot", {}, true, busy, status);
  const button = screen.getByRole("button", { name: t("agents.saveSchedule") }) as HTMLButtonElement;
  expect(button.closest("fieldset")?.disabled).toBe(true);
});

it("sends only explicit registered-domain metadata with null CAS from the shared boundary fixture", () => {
  const change = vi.fn();
  const mapping = { status: "unconfigured" as const, domain_id: null, domain_fqdn: null };
  render(<AgentModuleControls agent={{ ...agent, password_detection_domain: mapping }} module={{ module_id: "sli.windows.ad-dc", enabled: true,
    config: { source_name: "do-not-infer.example", connect_address: "dc.do-not-infer.example", policy_revision: "3" } }} busy={false} change={change}/>);
  expect((screen.getByLabelText(t("agents.passwordDomain.fqdn")) as HTMLInputElement).value).toBe("");
  fireEvent.change(screen.getByLabelText(t("agents.passwordDomain.fqdn")), { target: { value: domainRequest.password_detection_domain.fqdn } });
  fireEvent.submit(screen.getByRole("button", { name: t("agents.passwordDomain.save") }).closest("form")!);
  expect(change).toHaveBeenCalledExactlyOnceWith("modules", domainRequest);
  expect(screen.queryByText(/Это только сохранённая привязка|only a saved binding/)).toBeNull();
});

it.each([
  { name: "busy", busy: true, status: "active" as const, enabled: true, mapping: { status: "unconfigured" as const, domain_id: null, domain_fqdn: null } },
  { name: "inactive", busy: false, status: "disabled" as const, enabled: true, mapping: { status: "unconfigured" as const, domain_id: null, domain_fqdn: null } },
  { name: "disabled AD module", busy: false, status: "active" as const, enabled: false, mapping: { status: "unconfigured" as const, domain_id: null, domain_fqdn: null } },
  { name: "absent readback", busy: false, status: "active" as const, enabled: true, mapping: undefined },
  { name: "unsafe domain ID", busy: false, status: "active" as const, enabled: true, mapping: { status: "configured" as const, domain_id: Number.MAX_SAFE_INTEGER + 1, domain_fqdn: "synthetic.example" } },
])("blocks domain metadata mutation for $name even on direct form submission", ({ busy, status, enabled, mapping }) => {
  const change = vi.fn();
  render(<AgentModuleControls agent={{ ...agent, status, password_detection_domain: mapping }} module={{ module_id: "sli.windows.ad-dc", enabled, config: {} }} busy={busy} change={change}/>);
  const button = screen.getByRole("button", { name: t("agents.passwordDomain.save") }) as HTMLButtonElement;
  expect(button.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText(t("agents.passwordDomain.fqdn")), { target: { value: "synthetic.example" } });
  fireEvent.submit(button.closest("form")!);
  expect(change).not.toHaveBeenCalled();
});

it("preserves safe existing domain CAS and blocks established domain transfer", () => {
  const change = vi.fn();
  render(<AgentModuleControls agent={{ ...agent, password_detection_domain: { status: "configured", domain_id: 2147483648, domain_fqdn: "synthetic.example" } }}
    module={{ module_id: "sli.windows.ad-dc", enabled: true, config: { policy_revision: "3" } }} busy={false} change={change}/>);
  const input = screen.getByLabelText(t("agents.passwordDomain.fqdn")) as HTMLInputElement;
  expect(input.readOnly).toBe(true);
  fireEvent.submit(screen.getByRole("button", { name: t("agents.passwordDomain.save") }).closest("form")!);
  expect(change).toHaveBeenCalledExactlyOnceWith("modules", { ...domainRequest,
    password_detection_domain: { fqdn: "synthetic.example", expected_domain_id: 2147483648 } });
  fireEvent.change(input, { target: { value: "other.example" } });
  fireEvent.submit(screen.getByRole("button", { name: t("agents.passwordDomain.save") }).closest("form")!);
  expect(change).toHaveBeenCalledOnce();
});

it("refreshes controlled domain readback on changed mapping at the same global revision", () => {
  const change = vi.fn();
  const module = { module_id: "sli.windows.ad-dc", enabled: true, config: {} };
  const { rerender } = render(<AgentModuleControls agent={{ ...agent, password_detection_domain: { status: "unconfigured", domain_id: null, domain_fqdn: null } }} module={module} busy={false} change={change}/>);
  fireEvent.change(screen.getByLabelText(t("agents.passwordDomain.fqdn")), { target: { value: "unsaved.example" } });
  rerender(<AgentModuleControls agent={{ ...agent, password_detection_domain: { status: "configured", domain_id: 81, domain_fqdn: "stored.example" } }} module={module} busy={false} change={change}/>);
  expect((screen.getByLabelText(t("agents.passwordDomain.fqdn")) as HTMLInputElement).value).toBe("stored.example");
  fireEvent.submit(screen.getByRole("button", { name: t("agents.passwordDomain.save") }).closest("form")!);
  expect(change).toHaveBeenCalledExactlyOnceWith("modules", { ...domainRequest,
    password_detection_domain: { fqdn: "stored.example", expected_domain_id: 81 } });
});
