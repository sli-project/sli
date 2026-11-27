// @vitest-environment jsdom
import userEvent from "@testing-library/user-event";
import { chooseOption } from "../../../tests/select-option";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { api, ApiResponseError, type AgentFileAuditCatalog, type AgentFileAuditCommand, type AgentItem } from "../../api/client";
import { t } from "../../i18n";
import requests from "../../test-fixtures/file_audit_server_ui_requests.json";
import { AgentFileAuditControls } from "./agent-file-audit";
import { PluginSources } from "./plugin-sources";

vi.mock("../App", () => ({ useTimeZone: () => ({ timeZone: "UTC" }) }));

const request = requests.check;
const agent: AgentItem = {
  id: request.agent_id, host_id: request.agent_id, host_name: "files.example.invalid",
  status: "active", last_seen: null, policy_revision: request.expected_revision,
  applied_policy_revision: request.expected_revision, certificates: [], rights_probe: {},
  assigned_modules: [{ module_id: "sli.file-audit", enabled: true, config: request.config }],
};
let client: QueryClient;

function mount(connection: boolean, canEdit: boolean, agents = [agent]) {
  vi.spyOn(api, "setupStatus").mockResolvedValue({ sources: [], domains: [], domain_controllers: [] } as unknown as Awaited<ReturnType<typeof api.setupStatus>>);
  vi.spyOn(api, "agents").mockResolvedValue({ items: agents });
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>
    <PluginSources pluginId="sli.file-audit" connection={connection} canEdit={canEdit}/>
  </QueryClientProvider>);
}

afterEach(() => {
  cleanup();
  client.clear();
  const url = new URL(window.location.href);
  url.searchParams.delete("file_audit_agent");
  window.history.replaceState(window.history.state, "", url);
  vi.restoreAllMocks();
});

it("submits a server check from Connection and displays its matching native receipt", async () => {
  vi.spyOn(api, "agentFileAuditCatalog").mockResolvedValue({ state: "unsupported", items: [], saved_selection: null, saved_command: null });
  mount(true, true);
  let accepted: AgentFileAuditCommand;
  const action = vi.spyOn(api, "agentAction").mockImplementation(async (_, body) => {
    accepted = { ...(body.command as Omit<AgentFileAuditCommand, "agent_id">), agent_id: agent.id };
    return { status: "pending", state: "pending", command_id: accepted.command_id, policy_revision: agent.policy_revision + 1 };
  });
  const status = vi.spyOn(api, "agentFileAuditStatus").mockImplementation(async () => ({
    command: accepted, state: "verified", reported_at: "2026-10-25T00:00:00Z", may_own_audit: false,
    scopes: { [accepted.collection_scope_ids[0]]: { state: "verified", reason_code: "ok" } },
  }));
  const title = await screen.findByText(t("agents.fileAudit.title"));
  title.closest("details")!.open = true;
  await chooseOption(screen.getByLabelText(t("agents.fileAudit.sourceKind"), { selector: "button" }), "server");
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: agent.host_name! })));
  await screen.findByLabelText(t("agents.fileAudit.paths"));
  fireEvent.click(screen.getByRole("button", { name: t("agents.fileAudit.check") }));
  expect(await screen.findByText(t("agents.fileAudit.result.verified"))).toBeTruthy();
  expect(action).toHaveBeenCalledWith("file-audit", expect.objectContaining({
    agent_id: agent.id, expected_revision: agent.policy_revision, config: request.config,
    command: expect.objectContaining({ action: "check", policy_revision: String(agent.policy_revision + 1) }),
  }));
  expect(status).toHaveBeenCalledExactlyOnceWith(agent.id);
});

it("restores an authorized SMB selection on remount and distinguishes check from confirmed apply", async () => {
  const target: AgentItem = {
    ...agent, assigned_modules: [],
    collection_policy: { state: "active", interval_seconds: 60, batch_size: 32, rate_limit_per_minute: 120,
      spool_max_bytes: 67108864, manage_windows_audit: true },
  };
  const share = { share_name: "Pilot$", path: "C:\\Pilot", collection_scope_id: "pilot-scope" };
  const shareKey = JSON.stringify([target.id, "bound-source", share.collection_scope_id]);
  const reportName = t("file-audit.tabs.permission-changes");
  let catalog: AgentFileAuditCatalog = { state: "idle", items: [], saved_selection: null, saved_command: null };
  vi.spyOn(api, "agentFileAuditCatalog").mockImplementation(async () => catalog);
  const refresh = vi.spyOn(api, "requestAgentFileAuditCatalog").mockImplementation(async () =>
    catalog = { ...catalog, state: "pending" });
  const action = vi.spyOn(api, "agentAction").mockImplementation(async (_, body) => {
    expect(body.expected_revision).toBe(target.policy_revision);
    const command = body.command as NonNullable<AgentFileAuditCatalog["saved_command"]>;
    target.policy_revision++;
    catalog = { ...catalog, saved_selection: share, saved_report_share_key: shareKey, saved_command: command };
    return { status: "pending", state: "pending", command_id: command.command_id, policy_revision: target.policy_revision };
  });
  vi.spyOn(api, "agentFileAuditStatus").mockImplementation(async () => ({
    command: catalog.saved_command!, state: "verified", reported_at: "2026-10-25T00:00:00Z",
    may_own_audit: catalog.saved_command?.action === "apply",
    scopes: { [share.collection_scope_id]: { state: "verified", reason_code: "ok" } },
  }));
  const view = mount(true, true, [target]);
  (await screen.findByText(t("agents.fileAudit.title"))).closest("details")!.open = true;
  await chooseOption(screen.getByLabelText(t("agents.fileAudit.sourceKind"), { selector: "button" }), "server");
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: target.host_name! })));
  await waitFor(() => expect(refresh).toHaveBeenCalledTimes(1));
  expect(refresh.mock.calls[0][0]).toBe(target.id);
  expect(await screen.findByText(t("agents.fileAudit.catalog.pending"))).toBeTruthy();
  expect(screen.queryByRole("option", { name: share.share_name })).toBeNull();
  expect(action).not.toHaveBeenCalled();
  catalog = { ...catalog, state: "ready", items: [share] };
  await waitFor(() => expect(screen.queryByText(t("agents.fileAudit.catalog.pending"))).toBeNull(), { timeout: 4_500 });
  expect(refresh).toHaveBeenCalledTimes(1);
  await chooseOption(screen.getByLabelText(t("agents.fileAudit.catalog.share"), { selector: "button" }), share.collection_scope_id);
  const path = screen.getByLabelText(t("agents.fileAudit.catalog.path")) as HTMLInputElement;
  expect(path.value).toBe(share.path);
  expect(path.readOnly).toBe(true);
  expect(action).not.toHaveBeenCalled();

  fireEvent.click(screen.getByRole("button", { name: t("agents.fileAudit.check") }));
  expect(await screen.findByText(t("agents.fileAudit.result.verified"))).toBeTruthy();
  expect(screen.queryByRole("link", { name: reportName })).toBeNull();
  const checked = action.mock.calls[0][1];
  expect(checked).toMatchObject({ config: { source_kind: "server", roots: [expect.objectContaining(share)] },
    command: { action: "check", collection_scope_ids: [share.collection_scope_id] } });
  expect(checked).not.toHaveProperty("activate_collection");
  expect(checked).not.toHaveProperty("enabled");

  view.unmount();
  client.clear();
  mount(true, true, [target]);
  expect(await screen.findByRole("heading", { name: t("agents.fileAudit.catalog.checkResult") })).toBeTruthy();
  expect(refresh).toHaveBeenCalledTimes(1);
  expect(screen.getByLabelText(t("agents.fileAudit.catalog.share"), { selector: "button" }).textContent).toContain(share.share_name);
  expect(await screen.findByText(t("agents.fileAudit.result.verified"))).toBeTruthy();
  const confirm = vi.spyOn(window, "confirm").mockReturnValueOnce(false).mockReturnValueOnce(true);
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.enabled")));
  const apply = screen.getByRole("button", { name: t("agents.fileAudit.apply") });
  fireEvent.click(apply);
  expect(action).toHaveBeenCalledTimes(1);
  expect(screen.queryByRole("link", { name: reportName })).toBeNull();
  fireEvent.click(apply);
  expect(await screen.findByRole("heading", { name: t("agents.fileAudit.catalog.applyResult") })).toBeTruthy();
  expect(await screen.findByText(t("agents.fileAudit.result.verified"))).toBeTruthy();
  expect(confirm).toHaveBeenCalledTimes(2);
  expect(action.mock.calls[1][1]).toMatchObject({ enabled: true, activate_collection: true,
    config: { roots: [expect.objectContaining(share)] },
    command: { action: "apply", collection_scope_ids: [share.collection_scope_id] } });
  const report = new URL((await screen.findByRole("link", { name: reportName })).getAttribute("href")!, window.location.origin);
  expect(report.pathname).toBe("/app/report/file-audit.permission-changes");
  expect(report.searchParams.getAll("share")).toEqual([shareKey]);
  expect(Object.fromEntries(report.searchParams)).toMatchObject({
    period: "24h", source_kind: "server", path: share.path, operation: "permissions", include_nested: "true",
  });
}, 10_000);

it.each([
  { action: "check", state: "partial", reason: "coverage_incomplete", explanation: "checkCoverageIncomplete", permissionDenied: false },
  { action: "apply", state: "blocked", reason: "global_sacl_unknown", explanation: "applyGlobalSaclUnknown", permissionDenied: true },
] as const)("explains the saved $action result only while its receipt matches", async ({
  action: requestedAction, state, reason, explanation, permissionDenied,
}) => {
  const share = { share_name: "Pilot$", path: "C:\\Pilot", collection_scope_id: "pilot-scope" };
  const target = { ...agent, assigned_modules: [] };
  const command = {
    command_id: "saved-command", action: requestedAction, policy_revision: String(target.policy_revision),
    collection_scope_ids: [share.collection_scope_id],
  };
  const url = new URL(window.location.href);
  url.searchParams.set("file_audit_agent", target.id);
  window.history.replaceState(window.history.state, "", url);
  vi.spyOn(api, "agentFileAuditCatalog").mockResolvedValue({
    state: "ready", items: [share], saved_selection: share, saved_command: command,
    saved_report_share_key: JSON.stringify([target.id, "bound-source", share.collection_scope_id]),
  });
  const receipt = {
    command, state, reported_at: "2026-10-25T00:00:00Z", may_own_audit: false,
    scopes: { [share.collection_scope_id]: { state, reason_code: reason } },
  };
  const status = vi.spyOn(api, "agentFileAuditStatus").mockResolvedValue(receipt);
  const mutate = vi.spyOn(api, "agentAction");
  const message = t(`agents.fileAudit.result.${explanation}`, { share: share.share_name });
  const view = mount(true, true, [target]);
  expect(await screen.findByText(message)).toBeTruthy();

  view.unmount();
  client.clear();
  mount(true, true, [target]);
  expect(await screen.findByText(message)).toBeTruthy();
  expect(screen.getByLabelText(t("agents.fileAudit.catalog.share"), { selector: "button" }).textContent).toContain(share.share_name);
  expect((screen.getByLabelText(t("agents.fileAudit.catalog.path")) as HTMLInputElement).value).toBe(share.path);
  const reasonLabel = requestedAction === "apply" ? t("agents.fileAudit.reason.global_sacl_unknown") : reason;
  const technicalDetails = screen.getByText(reasonLabel).closest("details");
  if (requestedAction === "apply") expect(screen.queryByText(reason)).toBeNull();
  expect(technicalDetails?.querySelector("summary")?.textContent).toBe(t("agents.technicalDetails"));
  expect(technicalDetails?.open).toBe(false);
  expect(screen.queryByRole("link", { name: t("file-audit.tabs.permission-changes") })).toBeNull();

  if (permissionDenied) status.mockRejectedValueOnce(new ApiResponseError(403));
  else status.mockResolvedValueOnce({ ...receipt, command: { ...command, command_id: "different-command" } });
  fireEvent.click(screen.getByRole("button", { name: t("agents.fileAudit.result.refresh") }));
  expect(await screen.findByText(t(permissionDenied ? "agents.fileAudit.result.denied" : "agents.fileAudit.result.stale"))).toBeTruthy();
  expect(screen.queryByText(message)).toBeNull();
  expect(screen.queryByText(reasonLabel)).toBeNull();
  expect(screen.getByLabelText(t("agents.fileAudit.catalog.share"), { selector: "button" }).textContent).toContain(share.share_name);
  expect(mutate).not.toHaveBeenCalled();
});

it("keeps a manual share's explanation tied to the receipt scope", async () => {
  const command: AgentFileAuditCommand = {
    ...request.command, action: "check", agent_id: agent.id, collection_scope_ids: ["different-scope"],
  };
  vi.spyOn(api, "agentFileAuditStatus").mockResolvedValue({
    command, state: "partial", reported_at: "2026-10-25T00:00:00Z", may_own_audit: false,
    scopes: { "different-scope": { state: "partial", reason_code: "coverage_incomplete" } },
  });
  client = new QueryClient();
  render(<AgentFileAuditControls agents={[agent]} busy={false} change={vi.fn()} accepted={command}/>);
  screen.getByText(t("agents.fileAudit.title")).closest("details")!.open = true;
  await chooseOption(screen.getByLabelText(t("agents.fileAudit.sourceKind"), { selector: "button" }), "server");
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: agent.host_name! })));

  const root = request.config.roots[0];
  expect((screen.getByLabelText(t("agents.fileAudit.shares")) as HTMLTextAreaElement).value).toBe(root.share_name);
  expect(await screen.findByText(t("agents.fileAudit.result.partial"))).toBeTruthy();
  expect(screen.queryByText(t("agents.fileAudit.result.checkCoverageIncomplete", { share: root.share_name }))).toBeNull();
});

it.each(["ready", "denied"] as const)("keeps an existing catalog or leaves a denied catalog unread: %s", async (access) => {
  const target = { ...agent, assigned_modules: [] };
  const share = { share_name: "Pilot$", path: "C:\\Pilot", collection_scope_id: "pilot-scope" };
  const catalog = vi.spyOn(api, "agentFileAuditCatalog");
  if (access === "denied") catalog.mockRejectedValue(new ApiResponseError(403, "forbidden"));
  else catalog.mockResolvedValue({ state: "ready", items: [share], saved_selection: null, saved_command: null });
  const refresh = vi.spyOn(api, "requestAgentFileAuditCatalog");
  const action = vi.spyOn(api, "agentAction");
  mount(true, true, [target]);
  (await screen.findByText(t("agents.fileAudit.title"))).closest("details")!.open = true;
  await chooseOption(screen.getByLabelText(t("agents.fileAudit.sourceKind"), { selector: "button" }), "server");
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: target.host_name! })));
  if (access === "denied") {
    await screen.findByText(t("agents.fileAudit.catalog.unavailable"));
    const picker = screen.queryByLabelText(t("agents.fileAudit.catalog.share"), { selector: "button" });
    if (picker) await userEvent.click(picker);
    expect(screen.queryByRole("option", { name: share.share_name })).toBeNull();
    expect(screen.queryByRole("button", { name: t("agents.fileAudit.catalog.manualEntry") })).toBeNull();
  } else {
    await userEvent.click(await screen.findByLabelText(t("agents.fileAudit.catalog.share"), { selector: "button" }));
    expect(await screen.findByRole("option", { name: share.share_name })).toBeTruthy();
  }
  expect(catalog).toHaveBeenCalledExactlyOnceWith(target.id, expect.any(AbortSignal));
  expect(refresh).not.toHaveBeenCalled();
  expect(action).not.toHaveBeenCalled();
});

it.each(["unavailable", "incomplete", "transport"] as const)("allows a manual server check after catalog failure: %s", async (failure) => {
  const target = { ...agent, assigned_modules: [] };
  const catalog = vi.spyOn(api, "agentFileAuditCatalog");
  if (failure === "transport") catalog.mockRejectedValue(new TypeError("offline"));
  else catalog.mockResolvedValue({ state: failure, items: [], saved_selection: null, saved_command: null });
  let command: AgentFileAuditCommand;
  const action = vi.spyOn(api, "agentAction").mockImplementation(async (_, body) => {
    command = { ...(body.command as Omit<AgentFileAuditCommand, "agent_id">), agent_id: target.id };
    return { status: "pending", state: "pending", command_id: command.command_id, policy_revision: target.policy_revision + 1 };
  });
  vi.spyOn(api, "agentFileAuditStatus").mockImplementation(async () => ({
    command, state: "verified", reported_at: "2026-10-25T00:00:00Z", may_own_audit: false,
    scopes: { "manual-pilot": { state: "verified", reason_code: "ok" } },
  }));
  mount(true, true, [target]);
  (await screen.findByText(t("agents.fileAudit.title"))).closest("details")!.open = true;
  await chooseOption(screen.getByLabelText(t("agents.fileAudit.sourceKind"), { selector: "button" }), "server");
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: target.host_name! })));
  const manual = await screen.findByRole("button", { name: t("agents.fileAudit.catalog.manualEntry") });
  const check = screen.getByRole("button", { name: t("agents.fileAudit.check") }) as HTMLButtonElement;
  expect(check.disabled).toBe(true);
  expect(screen.queryByLabelText(t("agents.fileAudit.paths"))).toBeNull();
  fireEvent.click(manual);
  fireEvent.change(screen.getByLabelText(t("agents.fileAudit.paths")), { target: { value: "C:\\Pilot" } });
  fireEvent.change(screen.getByLabelText(t("agents.fileAudit.shares")), { target: { value: "Pilot$" } });
  fireEvent.change(screen.getByLabelText(t("agents.fileAudit.scopes")), { target: { value: "manual-pilot" } });
  expect(action).not.toHaveBeenCalled();
  fireEvent.click(check);
  expect(await screen.findByText(t("agents.fileAudit.result.verified"))).toBeTruthy();
  const body = action.mock.calls[0][1];
  expect(body).toMatchObject({ agent_id: target.id, expected_revision: target.policy_revision,
    config: { roots: [expect.objectContaining({ path: "C:\\Pilot", share_name: "Pilot$", collection_scope_id: "manual-pilot" })] },
    command: { action: "check", collection_scope_ids: ["manual-pilot"] } });
  expect(body).not.toHaveProperty("enabled");
  expect(body).not.toHaveProperty("activate_collection");
});

it.each([[false, true], [true, false]])("hides commands with connection=%s and canEdit=%s", async (connection, canEdit) => {
  const action = vi.spyOn(api, "agentAction");
  mount(connection, canEdit);
  await screen.findByRole("link", { name: t("plugins.next.connect_file_server") });
  expect(screen.queryByText(t("agents.fileAudit.title"))).toBeNull();
  expect(action).not.toHaveBeenCalled();
  expect(api.agents).not.toHaveBeenCalled();
});

it("binds workstation batch readbacks to each selected agent and revision", async () => {
  const workstation = { ...agent, assigned_modules: [{ module_id: "sli.workstations", enabled: true, config: {} }] };
  const second = { ...workstation, id: "00000000-0000-4000-8000-000000000002", host_name: "other.example.invalid", policy_revision: 5 };
  const commands = new Map<string, AgentFileAuditCommand>();
  mount(true, true, [workstation, second]);
  vi.spyOn(api, "agentAction").mockImplementation(async (_, body) => {
    expect(body.agents).toEqual([workstation, second].map((target) => ({
      agent_id: target.id, expected_revision: target.policy_revision,
    })));
    const items = [second, workstation].map((target) => {
      const policy_revision = target.policy_revision + 1;
      const command_id = 'command-' + target.id;
      commands.set(target.id, {
        agent_id: target.id, command_id, policy_revision: String(policy_revision), action: "check", collection_scope_ids: ["wsfile:0"],
      });
      return { agent_id: target.id, command_id, policy_revision, state: "pending" };
    });
    return { status: "pending", items };
  });
  const status = vi.spyOn(api, "agentFileAuditStatus").mockImplementation(async (id) => ({
    command: commands.get(id)!, state: "verified", reported_at: "2026-10-25T00:00:00Z", may_own_audit: false,
    scopes: { "wsfile:0": { state: "verified", reason_code: "ok" } },
  }));
  const title = await screen.findByText(t("agents.fileAudit.title"));
  title.closest("details")!.open = true;
  for (const target of [workstation, second]) {
    fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: target.host_name! })));
  }
  fireEvent.change(screen.getByLabelText(t("agents.fileAudit.paths")), { target: { value: "C:/Synthetic" } });
  fireEvent.click(screen.getByRole("button", { name: t("agents.fileAudit.check") }));
  await waitFor(() => expect(screen.getAllByText(t("agents.fileAudit.result.verified"))).toHaveLength(2));
  expect(status.mock.calls).toEqual([[workstation.id], [second.id]]);
});
