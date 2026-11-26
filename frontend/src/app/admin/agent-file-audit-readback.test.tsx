// @vitest-environment jsdom
import { chooseOption } from "../../../tests/select-option";
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
async function selectServer() {
  await chooseOption(screen.getByLabelText(t("agents.fileAudit.sourceKind"), { selector: "button" }), "server");
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: agent.host_name! })));
}
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });

it.each(["pending", "verified", "partial", "unexpected"])("reads the accepted selected command and distinguishes %s", async (state) => {
  vi.spyOn(api, "agentFileAuditStatus").mockResolvedValue(receipt(state));
  render(<AgentFileAuditControls {...props}/>);
  await selectServer();
  const expected = state === "unexpected" ? "unknown" : state;
  expect(await screen.findByText(t(`agents.fileAudit.result.${expected}` as MessageKey))).toBeTruthy();
  expect(api.agentFileAuditStatus).toHaveBeenCalledWith(agent.id);
  expect(screen.getByText(body.command.command_id).closest("details")?.open).toBe(false);
});

it.each(["command_id", "policy_revision", "action"])("does not accept a stale %s as verification", async (field) => {
  vi.spyOn(api, "agentFileAuditStatus").mockResolvedValue({ ...receipt(), command: { ...receipt().command, [field]: "other" } });
  render(<AgentFileAuditControls {...props}/>); await selectServer();
  expect(await screen.findByText(t("agents.fileAudit.result.stale"))).toBeTruthy();
  expect(screen.queryByText(t("agents.fileAudit.result.verified"))).toBeNull();
});

it("denies a revoked status without retaining successful evidence", async () => {
  const status = vi.spyOn(api, "agentFileAuditStatus").mockResolvedValueOnce(receipt()).mockRejectedValueOnce(new ApiResponseError(403));
  render(<AgentFileAuditControls {...props}/>); await selectServer();
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
  render(<AgentFileAuditControls {...props} agents={[agent, other]}/>); await selectServer();
  await waitFor(() => expect(resolve).toBeDefined());
  fireEvent.click(screen.getByLabelText(t("agents.fileAudit.agent", { host: other.host_name })));
  await act(async () => { resolve(receipt()); });
  expect(screen.queryByText(t("agents.fileAudit.result.verified"))).toBeNull();
  expect(screen.queryByText(body.command.command_id)).toBeNull();
});

it("hides the prior result while a newer mutation is pending or failed", async () => {
  vi.spyOn(api, "agentFileAuditStatus").mockResolvedValue(receipt());
  const view = render(<AgentFileAuditControls {...props}/>); await selectServer();
  expect(await screen.findByText(t("agents.fileAudit.result.verified"))).toBeTruthy();
  view.rerender(<AgentFileAuditControls {...props} busy accepted={undefined}/>);
  expect(screen.queryByText(t("agents.fileAudit.result.verified"))).toBeNull();
  view.rerender(<AgentFileAuditControls {...props} accepted={undefined}/>);
  expect(screen.queryByText(t("agents.fileAudit.result.verified"))).toBeNull();
});

it("never reads another agent's accepted command", async () => {
  const status = vi.spyOn(api, "agentFileAuditStatus");
  render(<AgentFileAuditControls {...props} accepted={{ ...accepted, agent_id: "other" }}/>); await selectServer();
  expect(status).not.toHaveBeenCalled();
});

it("keeps a missing or malformed receipt unknown, not successful", async () => {
  vi.spyOn(api, "agentFileAuditStatus").mockResolvedValue(null as never);
  render(<AgentFileAuditControls {...props}/>); await selectServer();
  expect(await screen.findByText(t("agents.fileAudit.result.unknown"))).toBeTruthy();
});

it("polls a pending receipt until the matching command is verified", async () => {
  vi.spyOn(api, "agentFileAuditStatus").mockResolvedValueOnce(receipt("pending")).mockResolvedValueOnce(receipt());
  render(<AgentFileAuditControls {...props}/>);
  await chooseOption(screen.getByLabelText(t("agents.fileAudit.sourceKind"), { selector: "button" }), "server");
  vi.useFakeTimers();
  fireEvent.click(screen.getByLabelText("Выбрать: synthetic.example.invalid"));
  await act(async () => { await Promise.resolve(); });
  expect(screen.getByText(t("agents.fileAudit.result.pending"))).toBeTruthy();
  await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
  expect(screen.getByText(t("agents.fileAudit.result.verified"))).toBeTruthy();
  await act(async () => { await vi.advanceTimersByTimeAsync(15_000); });
  expect(api.agentFileAuditStatus).toHaveBeenCalledTimes(2);
});

it("cannot display verified without confirmation of the selected scope", async () => {
  vi.spyOn(api, "agentFileAuditStatus").mockResolvedValue({ ...receipt(), scopes: {} });
  render(<AgentFileAuditControls {...props}/>); await selectServer();
  expect(await screen.findByText(t("agents.fileAudit.result.unknown"))).toBeTruthy();
});

it("keeps partial scope reasons in collapsed details", async () => {
  vi.spyOn(api, "agentFileAuditStatus").mockResolvedValue({ ...receipt("partial"), scopes: {
    [body.command.collection_scope_ids[0]]: { state: "blocked", reason_code: "managed_by_gpo" },
  } });
  render(<AgentFileAuditControls {...props}/>); await selectServer();
  expect(await screen.findByText(t("agents.fileAudit.result.partial"))).toBeTruthy();
  expect(screen.getByText("managed_by_gpo").closest("details")?.open).toBe(false);
});

it("does not present an older verified command as verification of an edited invalid draft", async () => {
  vi.spyOn(api, "agentFileAuditStatus").mockResolvedValue(receipt());
  const change = vi.fn();
  render(<AgentFileAuditControls {...props} change={change}/>); await selectServer();
  expect(await screen.findByText(t("agents.fileAudit.result.verified"))).toBeTruthy();
  fireEvent.change(screen.getByLabelText(t("agents.fileAudit.paths")), { target: { value: "invalid" } });
  expect(screen.queryByText(t("agents.fileAudit.result.verified"))).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: t("agents.fileAudit.check") }));
  expect(change).not.toHaveBeenCalled();
  expect(screen.queryByText(t("agents.fileAudit.result.verified"))).toBeNull();
});

it("stops automatic polling after a local wait timeout and can still verify on refresh", async () => {
  const status = vi.spyOn(api, "agentFileAuditStatus").mockResolvedValue({ ...receipt("pending"), scopes: {}, reported_at: null });
  render(<AgentFileAuditControls {...props}/>);
  await chooseOption(screen.getByLabelText(t("agents.fileAudit.sourceKind"), { selector: "button" }), "server");
  vi.useFakeTimers();
  fireEvent.click(screen.getByLabelText("Выбрать: synthetic.example.invalid"));
  await act(async () => { await Promise.resolve(); });
  expect(screen.getByText(t("agents.fileAudit.result.pending"))).toBeTruthy();
  expect(screen.getByText(t("agents.fileAudit.result.noScopeReceipt"))).toBeTruthy();

  await act(async () => { await vi.advanceTimersByTimeAsync(120_000); });
  expect(screen.getByText(t("agents.fileAudit.result.delayed"))).toBeTruthy();
  const callCount = status.mock.calls.length;
  await act(async () => { await vi.advanceTimersByTimeAsync(15_000); });
  expect(status).toHaveBeenCalledTimes(callCount);

  status.mockResolvedValueOnce(receipt());
  fireEvent.click(screen.getByRole("button", { name: t("agents.fileAudit.result.refresh") }));
  await act(async () => { await Promise.resolve(); });
  expect(screen.getByText(t("agents.fileAudit.result.verified"))).toBeTruthy();
});

it("identifies an unavailable status endpoint without inferring command failure", async () => {
  vi.spyOn(api, "agentFileAuditStatus").mockRejectedValue(new ApiResponseError(503));
  render(<AgentFileAuditControls {...props}/>); await selectServer();
  expect(await screen.findByText(t("agents.fileAudit.result.unavailable"))).toBeTruthy();
  expect(screen.queryByText(t("agents.fileAudit.result.verified"))).toBeNull();
});

it.each([["failed", "native_unavailable"], ["blocked", "managed_by_gpo"]])("shows an exact %s receipt and its scope reason", async (state, reason_code) => {
  vi.spyOn(api, "agentFileAuditStatus").mockResolvedValue({ ...receipt(state), scopes: {
    [body.command.collection_scope_ids[0]]: { state, reason_code },
  } });
  render(<AgentFileAuditControls {...props}/>); await selectServer();
  expect(await screen.findByText(t(`agents.fileAudit.result.${state}` as MessageKey))).toBeTruthy();
  expect(screen.getByText(reason_code).closest("details")).toBe(screen.getByText(t("agents.fileAudit.title")).closest("details"));
});

it("keeps an unmatched scope failure unknown", async () => {
  vi.spyOn(api, "agentFileAuditStatus").mockResolvedValue({ ...receipt("failed"), scopes: {
    unrelated: { state: "failed", reason_code: "native_unavailable" },
  } });
  render(<AgentFileAuditControls {...props}/>); await selectServer();
  expect(await screen.findByText(t("agents.fileAudit.result.unknown"))).toBeTruthy();
  expect(screen.queryByText("native_unavailable")).toBeNull();
});

it("shows the ACL read step and numeric code from the matching failed check", async () => {
  vi.spyOn(api, "agentFileAuditStatus").mockResolvedValue({ ...receipt("failed"), scopes: {
    [body.command.collection_scope_ids[0]]: {
      state: "failed", reason_code: "native_unavailable", read_error: { stage: "acl", code_kind: "win32", code: 5 },
    },
  } });
  render(<AgentFileAuditControls {...props}/>); await selectServer();
  expect(await screen.findByText(t("agents.fileAudit.readError.acl"))).toBeTruthy();
  expect(screen.getByText(t("agents.fileAudit.readError.code", { code: 5 }))).toBeTruthy();
  expect(screen.queryByText(t("agents.fileAudit.result.verified"))).toBeNull();
});

it("shows the specific local group failure and Windows code for a partial check", async () => {
  vi.spyOn(api, "agentFileAuditStatus").mockResolvedValue({ ...receipt("partial"), scopes: {
    [body.command.collection_scope_ids[0]]: { state: "partial", reason_code: "local_groups_unavailable:2221" },
  } });
  render(<AgentFileAuditControls {...props}/>); selectServer();
  expect(await screen.findByText(t("agents.fileAudit.result.partial"))).toBeTruthy();
  expect(screen.getByText(t("agents.fileAudit.reason.local_groups_unavailable") + " " +
    t("agents.fileAudit.readError.code", { code: 2221 }))).toBeTruthy();
  expect(screen.queryByText("local_groups_unavailable:2221")).toBeNull();
});
