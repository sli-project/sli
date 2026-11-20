import { expect, it } from "vitest";
import { auditAgentHref } from "./agent-navigation";

const agent = "00000000-0000-4000-8000-000000000001";
it.each([["?domain=7", "domain=7"], ["?domain_id=8", "domain=8"], ["?scope=all", "scope=all"]])("preserves exact agent and shell context %s", (search, scope) => {
  expect(auditAgentHref(true, "audit-state", agent, search)).toBe(`/app/agents?agent_id=${agent}&${scope}#agent-${agent}`);
});
it("does not infer audit-control access from report access", () => {
  expect(auditAgentHref(false, "audit-state", agent, "")).toBeNull();
  expect(auditAgentHref(true, "actions", agent, "")).toBeNull();
});
it.each([null, undefined, 42, "", " ", "not-an-id", `${agent}&agent_id=other`, ` ${agent}`])("rejects missing or invalid agent identity %s", (id) => {
  expect(auditAgentHref(true, "audit-state", id, "")).toBeNull();
});
