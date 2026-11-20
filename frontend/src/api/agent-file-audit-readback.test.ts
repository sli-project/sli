import { afterEach, expect, it, vi } from "vitest";
import { acceptedAgentFileAuditCommand, api, ApiResponseError } from "./client";
import requests from "../test-fixtures/file_audit_server_ui_requests.json";
const body = requests.check;
const response = { state: "pending", command_id: body.command.command_id, policy_revision: body.expected_revision + 1 };
it("binds the accepted singleton response to its submitted agent and action", () => {
  expect(acceptedAgentFileAuditCommand(body, response)).toEqual({ agent_id: body.agent_id, ...body.command });
});
it.each([
  { ...response, state: "verified" }, { ...response, command_id: "old" }, { ...response, policy_revision: 999 },
  { ...response, policy_revision: "3" }, {}, null,
])("rejects malformed or mismatched acceptance %j", (result) => {
  expect(acceptedAgentFileAuditCommand(body, result)).toBeNull();
});
it("does not convert a batch or non-audit request into a singleton receipt", () => {
  expect(acceptedAgentFileAuditCommand({ agents: [{ agent_id: body.agent_id }] }, response)).toBeNull();
  expect(acceptedAgentFileAuditCommand({ ...body, command: { ...body.command, action: "other" } }, response)).toBeNull();
});

afterEach(() => { vi.unstubAllGlobals(); });
it("reads only the selected agent through the existing authenticated GET", async () => {
  const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ command: body.command, state: "pending" }), { status: 200 }));
  vi.stubGlobal("fetch", fetch);
  expect((await api.agentFileAuditStatus("agent/with?delimiter")).state).toBe("pending");
  expect(fetch).toHaveBeenCalledWith("/api/v1/admin/agents/file-audit?agent_id=agent%2Fwith%3Fdelimiter", expect.objectContaining({ credentials: "same-origin" }));
});
it("preserves structured denial from the existing GET", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: "file_audit_request_denied" }), { status: 403 })));
  await expect(api.agentFileAuditStatus(body.agent_id)).rejects.toBeInstanceOf(ApiResponseError);
});
