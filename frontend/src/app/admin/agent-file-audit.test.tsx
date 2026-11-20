// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import type { AgentItem } from "../../api/client";
import { t } from "../../i18n";
import { AgentFileAuditControls } from "./agent-file-audit";
import serverRequests from "../../test-fixtures/file_audit_server_ui_requests.json";

const agent = (id: string): AgentItem => ({ id, host_id: id, host_name: `fixture-${id.slice(-1)}.example.invalid`, status: "active", last_seen: null,
  policy_revision: 2, applied_policy_revision: 2, certificates: [], rights_probe: {},
  collection_policy: { state: "active", interval_seconds: 60, batch_size: 32, rate_limit_per_minute: 120,
    spool_max_bytes: 67108864, manage_windows_audit: true },
  assigned_modules: [{ module_id: "sli.workstations", enabled: true, config: {} }] });
const first = agent("00000000-0000-4000-8000-000000000001");
const second = agent("00000000-0000-4000-8000-000000000002");
afterEach(cleanup);

it("defaults off and sends an explicit selected group with local roots and administrator exclusions", () => {
  const change = vi.fn();
  render(<AgentFileAuditControls agents={[first, second]} busy={false} change={change}/>);
  expect(change).not.toHaveBeenCalled();
  expect((screen.getByLabelText(t("agents.fileAudit.enabled")) as HTMLInputElement).checked).toBe(false);
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: first.host_name! })));
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: second.host_name! })));
  fireEvent.change(screen.getByLabelText(t("agents.fileAudit.paths")), { target: { value: "C:\\Synthetic" } });
  fireEvent.change(screen.getByLabelText(t("agents.fileAudit.exclusions")), { target: { value: "S-1-5-21-1-2-3-1003" } });
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.enabled")));
  fireEvent.click(screen.getByRole("button", { name: t("agents.fileAudit.apply") }));
  expect(change).toHaveBeenCalledWith("file-audit", {
    agents: [first, second].map(({ id, policy_revision }) => ({ agent_id: id, expected_revision: policy_revision })),
    enabled: true, action: "apply", activate_collection: true, config: { source_kind: "workstation", service_account_exclusions: ["S-1-5-21-1-2-3-1003"],
      roots: [{ collection_scope_id: "wsfile:0", share_name: "", path: "C:\\Synthetic", important: false,
        sacl: { trustee_sids: ["S-1-1-0"], inherit_files: true, inherit_directories: true } }] },
  });
});

it("restores the original configured roots and disables collection without inventing a new scope", () => {
  const change = vi.fn();
  const roots = [{ collection_scope_id: "synthetic-existing", share_name: "", path: "C:\\Synthetic", important: true,
    sacl: { trustee_sids: ["S-1-5-11"], inherit_files: false, inherit_directories: true } }];
  const configured = { ...first, assigned_modules: [...first.assigned_modules,
    { module_id: "sli.file-audit", enabled: true, config: { source_kind: "workstation", roots, service_account_exclusions: [] } }] };
  render(<AgentFileAuditControls agents={[configured]} busy={false} change={change}/>);
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: first.host_name! })));
  fireEvent.click(screen.getByRole("button", { name: t("agents.fileAudit.restore") }));
  expect(change).toHaveBeenCalledWith("file-audit", expect.objectContaining({ enabled: false, action: "restore",
    config: expect.objectContaining({ roots }) }));
});

it("blocks audit changes when Windows audit management is disabled", () => {
  render(<AgentFileAuditControls agents={[{ ...first, collection_policy: undefined }]} busy={false} change={vi.fn()}/>);
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: first.host_name! })));
  expect((screen.getByRole("button", { name: t("agents.fileAudit.apply") }) as HTMLButtonElement).disabled).toBe(true);
});

it("preserves individual read profiles when saving an existing policy", () => {
  const change = vi.fn();
  const roots = [false, true].map((important, index) => ({ collection_scope_id: `synthetic:${index}`, share_name: "",
    path: `C:\\Synthetic${index}`, important, sacl: { trustee_sids: ["S-1-5-11"], inherit_files: true, inherit_directories: true } }));
  render(<AgentFileAuditControls agents={[{ ...first, assigned_modules: [...first.assigned_modules,
    { module_id: "sli.file-audit", enabled: true, config: { source_kind: "workstation", roots } }] }]} busy={false} change={change}/>);
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: first.host_name! })));
  fireEvent.click(screen.getByRole("button", { name: t("agents.fileAudit.check") }));
  expect(change).toHaveBeenCalledWith("file-audit", expect.objectContaining({ config: expect.objectContaining({ roots }) }));
});

it("keeps rollback available when the workstation module has been disabled", () => {
  const roots = [{ collection_scope_id: "synthetic-existing", share_name: "", path: "C:\\Synthetic", important: false,
    sacl: { trustee_sids: ["S-1-1-0"], inherit_files: true, inherit_directories: true } }];
  const change = vi.fn();
  render(<AgentFileAuditControls agents={[{ ...first, assigned_modules: [
    { module_id: "sli.workstations", enabled: false, config: {} },
    { module_id: "sli.file-audit", enabled: false, config: { source_kind: "workstation", roots } },
  ] }]} busy={false} change={change}/>);
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: first.host_name! })));
  const restore = screen.getByRole("button", { name: t("agents.fileAudit.restore") }) as HTMLButtonElement;
  expect(restore.disabled).toBe(false);
  fireEvent.click(restore);
  expect(change).toHaveBeenCalledWith("file-audit", expect.objectContaining({ action: "restore", enabled: false }));
});

it("activates a deliberately selected server from zero with explicit share and scope", () => {
  const change = vi.fn();
  render(<AgentFileAuditControls agents={[{ ...first, assigned_modules: [] }, second]} busy={false} change={change}/>);
  fireEvent.change(screen.getByLabelText(t("agents.fileAudit.sourceKind")), { target: { value: "server" } });
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: first.host_name! })));
  fireEvent.change(screen.getByLabelText(t("agents.fileAudit.paths")), { target: { value: "C:\\Synthetic" } });
  fireEvent.change(screen.getByLabelText(t("agents.fileAudit.shares")), { target: { value: "Synthetic" } });
  fireEvent.change(screen.getByLabelText(t("agents.fileAudit.scopes")), { target: { value: "server:synthetic" } });
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.enabled")));
  fireEvent.click(screen.getByRole("button", { name: t("agents.fileAudit.apply") }));
  expect(change).toHaveBeenCalledWith("file-audit", expect.objectContaining({ agent_id: first.id, expected_revision: 2,
    enabled: true, activate_collection: true, command: expect.objectContaining({ action: "apply",
      contract_id: "sli.file-audit.audit-command.v1", command_id: expect.any(String), policy_revision: "3", collection_scope_ids: ["server:synthetic"] }),
    config: expect.objectContaining({ source_kind: "server", roots: [expect.objectContaining({
      collection_scope_id: "server:synthetic", share_name: "Synthetic", path: "C:\\Synthetic" })] }) }));
  expect(change.mock.calls[0][1]).not.toHaveProperty("agents");
  expect(change.mock.calls[0][1]).not.toHaveProperty("action");
});

it.each(["check", "apply", "restore"] as const)("emits the strict singleton %s command from the shared boundary fixture and preserves config", (action) => {
  const change = vi.fn();
  const body = serverRequests[action];
  const uuid = vi.spyOn(crypto, "randomUUID").mockReturnValue(body.command.command_id as `${string}-${string}-${string}-${string}-${string}`);
  try {
    render(<AgentFileAuditControls agents={[{ ...first, assigned_modules: [
      { module_id: "sli.file-audit", enabled: true, config: body.config }] }]} busy={false} change={change}/>);
    fireEvent.change(screen.getByLabelText(t("agents.fileAudit.sourceKind")), { target: { value: "server" } });
    fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: first.host_name! })));
    fireEvent.click(screen.getByRole("button", { name: t(`agents.fileAudit.${action}`) }));
    expect(change).toHaveBeenCalledExactlyOnceWith("file-audit", body);
    expect(uuid).toHaveBeenCalledTimes(1);
  } finally { uuid.mockRestore(); }
});
it("requires server share and scope and never enables management implicitly", () => {
  const change = vi.fn();
  render(<AgentFileAuditControls agents={[{ ...first, assigned_modules: [], collection_policy: undefined }]} busy={false} change={change}/>);
  fireEvent.change(screen.getByLabelText(t("agents.fileAudit.sourceKind")), { target: { value: "server" } });
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: first.host_name! })));
  fireEvent.change(screen.getByLabelText(t("agents.fileAudit.paths")), { target: { value: "C:\\Synthetic" } });
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.enabled")));
  fireEvent.click(screen.getByRole("button", { name: t("agents.fileAudit.check") }));
  expect(change).not.toHaveBeenCalled();
  expect(screen.getByRole("alert")).toBeTruthy();
  expect(screen.getByText(t("agents.fileAudit.managementHint"))).toBeTruthy();
  expect((screen.getByRole("button", { name: t("agents.fileAudit.apply") }) as HTMLButtonElement).disabled).toBe(true);
});

it("rejects heterogeneous bound workstation configurations and never offers them in server mode", () => {
  const change = vi.fn();
  const configured = [first, second].map((item, index) => ({ ...item, assigned_modules: [...item.assigned_modules,
    { module_id: "sli.file-audit", enabled: true, config: { source_kind: "workstation", roots: [{
      collection_scope_id: `bound:${index}`, share_name: "", path: "C:\\Bound", important: false,
      sacl: { trustee_sids: ["S-1-1-0"], inherit_files: true, inherit_directories: true } }] } }] }));
  render(<AgentFileAuditControls agents={configured} busy={false} change={change}/>);
  for (const item of configured) fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: item.host_name! })));
  expect(screen.getByText(t("agents.fileAudit.incompatible"))).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: t("agents.fileAudit.apply") }));
  expect(change).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText(t("agents.fileAudit.sourceKind")), { target: { value: "server" } });
  expect(screen.queryByLabelText(t("agents.fileAudit.agent", { host: first.host_name! }))).toBeNull();
});

it.each([true, false])("blocks mixed bound and unbound workstations in either selection order (bound first: %s)", (boundFirst) => {
  const change = vi.fn();
  const bound = { ...first, assigned_modules: [...first.assigned_modules, { module_id: "sli.file-audit", enabled: true,
    config: { source_kind: "workstation", max_events: 17, roots: [{ collection_scope_id: "bound:scope", share_name: "",
      path: "C:\\Bound", important: true, sacl: { trustee_sids: ["S-1-5-11"], inherit_files: false, inherit_directories: true } }] } }] };
  render(<AgentFileAuditControls agents={[bound, second]} busy={false} change={change}/>);
  for (const item of boundFirst ? [bound, second] : [second, bound]) {
    fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: item.host_name! })));
  }
  expect(screen.getByText(t("agents.fileAudit.incompatible"))).toBeTruthy();
  for (const action of ["check", "apply", "restore"] as const) {
    const button = screen.getByRole("button", { name: t(`agents.fileAudit.${action}`) }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.click(button);
  }
  expect(change).not.toHaveBeenCalled();
});


it.each(["shares", "scopes"] as const)("rejects edited existing server %s without dispatching a different or silently retained identity", (field) => {
  const change = vi.fn();
  const roots = [{ collection_scope_id: "server:original", share_name: "Original", path: "C:\\Synthetic", important: true,
    sacl: { trustee_sids: ["S-1-5-11"], inherit_files: false, inherit_directories: true } }];
  const configured = { ...first, assigned_modules: [
    { module_id: "sli.file-audit", enabled: true, config: { source_kind: "server", roots } }] };
  render(<AgentFileAuditControls agents={[configured]} busy={false} change={change}/>);
  fireEvent.change(screen.getByLabelText(t("agents.fileAudit.sourceKind")), { target: { value: "server" } });
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: first.host_name! })));
  fireEvent.change(screen.getByLabelText(t(`agents.fileAudit.${field}`)), { target: { value: "Changed" } });
  for (const action of ["check", "apply"] as const) {
    fireEvent.click(screen.getByRole("button", { name: t(`agents.fileAudit.${action}`) }));
    expect(change).not.toHaveBeenCalled();
    expect(screen.getByRole("alert").textContent).toBe(t("agents.fileAudit.identityImmutable"));
  }
  fireEvent.change(screen.getByLabelText(t(`agents.fileAudit.${field}`)), { target: { value: field === "shares" ? "Original" : "server:original" } });
  fireEvent.click(screen.getByRole("button", { name: t("agents.fileAudit.check") }));
  expect(change).toHaveBeenCalledWith("file-audit", expect.objectContaining({ config: expect.objectContaining({ roots }) }));
  expect(screen.queryByRole("alert")).toBeNull();
});

it("distinguishes unnamed agents through linked technical details without using UUID as the name", () => {
  const change = vi.fn();
  render(<AgentFileAuditControls agents={[{ ...first, host_name: null }, { ...second, host_name: null }]} busy={false} change={change}/>);
  const inputs = screen.getAllByLabelText(t("agents.fileAudit.agent", { host: t("agents.unknownHost") })) as HTMLInputElement[];
  expect(inputs).toHaveLength(2);
  for (const [index, item] of [first, second].entries()) {
    const details = document.getElementById(inputs[index].getAttribute("aria-describedby")!) as HTMLDetailsElement;
    expect(details.open).toBe(false);
    expect(details.textContent).toContain(item.id);
    expect(inputs[index].id).toContain(item.id);
    expect(inputs[index].value).toBe(item.id);
  }
  fireEvent.click(inputs[1]);
  expect(inputs[1].checked).toBe(true);
  expect(inputs[0].checked).toBe(false);
  expect(change).not.toHaveBeenCalled();
});
