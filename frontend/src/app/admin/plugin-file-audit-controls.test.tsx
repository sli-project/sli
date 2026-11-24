// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { api, type AgentFileAuditCommand, type AgentItem } from "../../api/client";
import { t } from "../../i18n";
import requests from "../../test-fixtures/file_audit_server_ui_requests.json";
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
  render(<QueryClientProvider client={client}>
    <PluginSources pluginId="sli.file-audit" connection={connection} canEdit={canEdit}/>
  </QueryClientProvider>);
}

afterEach(() => {
  cleanup();
  client.clear();
  vi.restoreAllMocks();
});

it("submits a server check from Connection and displays its matching native receipt", async () => {
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
  fireEvent.change(screen.getByLabelText(t("agents.fileAudit.sourceKind")), { target: { value: "server" } });
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: agent.host_name! })));
  fireEvent.click(screen.getByRole("button", { name: t("agents.fileAudit.check") }));
  expect(await screen.findByText(t("agents.fileAudit.result.verified"))).toBeTruthy();
  expect(action).toHaveBeenCalledWith("file-audit", expect.objectContaining({
    agent_id: agent.id, expected_revision: agent.policy_revision, config: request.config,
    command: expect.objectContaining({ action: "check", policy_revision: String(agent.policy_revision + 1) }),
  }));
  expect(status).toHaveBeenCalledExactlyOnceWith(agent.id);
});

it.each([[false, true], [true, false]])("hides commands with connection=%s and canEdit=%s", async (connection, canEdit) => {
  const action = vi.spyOn(api, "agentAction");
  mount(connection, canEdit);
  await screen.findByText(t("pluginPage.noSources"));
  expect(screen.queryByText(t("agents.fileAudit.title"))).toBeNull();
  expect(action).not.toHaveBeenCalled();
  if (!canEdit) expect(api.agents).not.toHaveBeenCalled();
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
