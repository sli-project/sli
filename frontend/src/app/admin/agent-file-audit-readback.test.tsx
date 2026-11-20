// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { api, ApiResponseError, type AgentItem, type AgentFileAuditCommand, type AgentFileAuditStatus } from "../../api/client";
import { t, type MessageKey } from "../../i18n";
import requests from "../../test-fixtures/file_audit_server_ui_requests.json";
import { AgentFileAuditControls } from "./agent-file-audit";

const body = requests.check;
const agent: AgentItem = { id: body.agent_id, host_id: body.agent_id, host_name: "synthetic.example.invalid",
  status: "active", last_seen: null, policy_revision: body.expected_revision, applied_policy_revision: body.expected_revision,
  certificates: [], rights_probe: {}, assigned_modules: [{ module_id: "sli.file-audit", enabled: true, config: body.config }] };
const accepted: AgentFileAuditCommand = { agent_id: agent.id, ...body.command, action: "check" };
const receipt = (state = "verified"): AgentFileAuditStatus => ({ command: { ...body.command, action: "check" }, state, reported_at: "2026-10-25T00:00:00Z",
  may_own_audit: false, scopes: { [body.command.collection_scope_ids[0]]: { state: "verified", reason_code: "ok" } } });
const props = { agents: [agent], busy: false, change: vi.fn(), accepted };
function selectServer() {
  fireEvent.change(screen.getByLabelText(t("agents.fileAudit.sourceKind")), { target: { value: "server" } });
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: agent.host_name! })));
}
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });

it.each(["pending", "verified", "partial", "unexpected"])("reads the accepted selected command and distinguishes %s", async (state) => {
  vi.spyOn(api, "agentFileAuditStatus").mockResolvedValue(receipt(state));
  render(<AgentFileAuditControls {...props}/>);
  selectServer();
  const expected = state === "unexpected" ? "unknown" : state;
  expect(await screen.findByText(t(`agents.fileAudit.result.${expected}` as MessageKey))).toBeTruthy();
  expect(api.agentFileAuditStatus).toHaveBeenCalledWith(agent.id);
  expect(screen.getByText(body.command.command_id).closest("details")?.open).toBe(false);
});

it.each(["command_id", "policy_revision", "action"])("does not accept a stale %s as verification", async (field) => {
  vi.spyOn(api, "agentFileAuditStatus").mockResolvedValue({ ...receipt(), command: { ...receipt().command, [field]: "other" } });
  render(<AgentFileAuditControls {...props}/>); selectServer();
  expect(await screen.findByText(t("agents.fileAudit.result.stale"))).toBeTruthy();
  expect(screen.queryByText(t("agents.fileAudit.result.verified"))).toBeNull();
});

it("denies a revoked status without retaining successful evidence", async () => {
  const status = vi.spyOn(api, "agentFileAuditStatus").mockResolvedValueOnce(receipt()).mockRejectedValueOnce(new ApiResponseError(403));
  render(<AgentFileAuditControls {...props}/>); selectServer();
  expect(await screen.findByText(t("agents.fileAudit.result.verified"))).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: t("agents.fileAudit.result.refresh") }));
  expect(await screen.findByText(t("agents.fileAudit.result.denied"))).toBeTruthy();
  expect(screen.queryByText(t("agents.fileAudit.result.verified"))).toBeNull();
  expect(status).toHaveBeenCalledTimes(2);
});

it("ignores late readback after the selected agent changes", async () => {
  let resolve!: (value: ReturnType<typeof receipt>) => void;
  vi.spyOn(api, "agentFileAuditStatus").mockImplementation(() => new Promise((done) => { resolve = done; }));
  const other = { ...agent, id: "00000000-0000-4000-8000-000000000099", host_name: "other.example.invalid" };
  render(<AgentFileAuditControls {...props} agents={[agent, other]}/>); selectServer();
  await waitFor(() => expect(resolve).toBeDefined());
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: other.host_name })));
  await act(async () => { resolve(receipt()); });
  expect(screen.queryByText(t("agents.fileAudit.result.verified"))).toBeNull();
  expect(screen.queryByText(body.command.command_id)).toBeNull();
});

it("hides the prior result while a newer mutation is pending or failed", async () => {
  vi.spyOn(api, "agentFileAuditStatus").mockResolvedValue(receipt());
  const view = render(<AgentFileAuditControls {...props}/>); selectServer();
  expect(await screen.findByText(t("agents.fileAudit.result.verified"))).toBeTruthy();
  view.rerender(<AgentFileAuditControls {...props} busy accepted={undefined}/>);
  expect(screen.queryByText(t("agents.fileAudit.result.verified"))).toBeNull();
  view.rerender(<AgentFileAuditControls {...props} accepted={undefined}/>);
  expect(screen.queryByText(t("agents.fileAudit.result.verified"))).toBeNull();
});

it("never reads another agent's accepted command", () => {
  const status = vi.spyOn(api, "agentFileAuditStatus");
  render(<AgentFileAuditControls {...props} accepted={{ ...accepted, agent_id: "other" }}/>); selectServer();
  expect(status).not.toHaveBeenCalled();
});

it("keeps a missing or malformed receipt unknown, not successful", async () => {
  vi.spyOn(api, "agentFileAuditStatus").mockResolvedValue(null as never);
  render(<AgentFileAuditControls {...props}/>); selectServer();
  expect(await screen.findByText(t("agents.fileAudit.result.unknown"))).toBeTruthy();
});

it("polls a pending receipt until the matching command is verified", async () => {
  vi.useFakeTimers();
  vi.spyOn(api, "agentFileAuditStatus").mockResolvedValueOnce(receipt("pending")).mockResolvedValueOnce(receipt());
  render(<AgentFileAuditControls {...props}/>); selectServer();
  await act(async () => { await Promise.resolve(); });
  expect(screen.getByText(t("agents.fileAudit.result.pending"))).toBeTruthy();
  await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
  expect(screen.getByText(t("agents.fileAudit.result.verified"))).toBeTruthy();
  await act(async () => { await vi.advanceTimersByTimeAsync(15_000); });
  expect(api.agentFileAuditStatus).toHaveBeenCalledTimes(2);
});

it("cannot display verified without confirmation of the selected scope", async () => {
  vi.spyOn(api, "agentFileAuditStatus").mockResolvedValue({ ...receipt(), scopes: {} });
  render(<AgentFileAuditControls {...props}/>); selectServer();
  expect(await screen.findByText(t("agents.fileAudit.result.unknown"))).toBeTruthy();
});

it("keeps partial scope reasons in collapsed details", async () => {
  vi.spyOn(api, "agentFileAuditStatus").mockResolvedValue({ ...receipt("partial"), scopes: {
    [body.command.collection_scope_ids[0]]: { state: "blocked", reason_code: "managed_by_gpo" },
  } });
  render(<AgentFileAuditControls {...props}/>); selectServer();
  expect(await screen.findByText(t("agents.fileAudit.result.partial"))).toBeTruthy();
  expect(screen.getByText("managed_by_gpo").closest("details")?.open).toBe(false);
});

it("does not present an older verified command as verification of an edited invalid draft", async () => {
  vi.spyOn(api, "agentFileAuditStatus").mockResolvedValue(receipt());
  const change = vi.fn();
  render(<AgentFileAuditControls {...props} change={change}/>); selectServer();
  expect(await screen.findByText(t("agents.fileAudit.result.verified"))).toBeTruthy();
  fireEvent.change(screen.getByLabelText(t("agents.fileAudit.paths")), { target: { value: "invalid" } });
  expect(screen.queryByText(t("agents.fileAudit.result.verified"))).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: t("agents.fileAudit.check") }));
  expect(change).not.toHaveBeenCalled();
  expect(screen.queryByText(t("agents.fileAudit.result.verified"))).toBeNull();
});
