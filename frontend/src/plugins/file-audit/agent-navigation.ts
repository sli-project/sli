import { withDomain } from "../../app/domain-navigation";

/** Navigation only; matching the owner-only audit controls does not grant access. */
export function auditAgentHref(owner: boolean, tab: string, agentId: unknown, search: string): string | null {
  if (owner !== true || tab !== "audit-state" || typeof agentId !== "string"
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(agentId)) return null;
  const id = encodeURIComponent(agentId);
  return withDomain(`/app/agents?agent_id=${id}#agent-${id}`, search);
}
