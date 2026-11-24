import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { acceptedAgentFileAuditCommand, api, ApiResponseError, type AgentFileAuditCatalog, type AgentFileAuditCommand, type AgentItem } from "../../api/client";
import { t } from "../../i18n";
import { AgentFileAuditControls, AgentFileAuditReadback } from "./agent-file-audit";
import { agentHostName } from "./agent-actions";

export const fileAuditAgentParameter = "file_audit_agent";
const catalogKey = (agentId: string | null) => ["admin-file-audit-catalog", agentId] as const;

export function PluginFileAuditControls({ agents }: { agents: AgentItem[] }) {
  const client = useQueryClient();
  const [agentId, setAgentId] = useState(() => new URLSearchParams(window.location.search).get(fileAuditAgentParameter));
  const catalog = useQuery<AgentFileAuditCatalog>({
    queryKey: catalogKey(agentId),
    enabled: agentId !== null && agents.some((agent) => agent.id === agentId && agent.status === "active"),
    queryFn: async ({ signal }) => {
      try {
        return await api.agentFileAuditCatalog(agentId!, signal);
      } catch (error) {
        if (error instanceof ApiResponseError && [404, 501].includes(error.status))
          return { state: "unsupported", items: [], saved_selection: null, saved_command: null };
        throw error;
      }
    },
    refetchInterval: (query) => query.state.data?.state === "pending" ? 3_000 : false,
  });
  const refresh = useMutation({
    mutationFn: api.requestAgentFileAuditCatalog,
    onMutate: (id) => client.cancelQueries({ queryKey: catalogKey(id) }),
    onSuccess: (data, id) => client.setQueryData(catalogKey(id), data),
  });
  const selectAgent = (id: string | null) => {
    const url = new URL(window.location.href);
    if (id) url.searchParams.set(fileAuditAgentParameter, id);
    else url.searchParams.delete(fileAuditAgentParameter);
    window.history.replaceState(window.history.state, "", url);
    refresh.reset();
    setAgentId(id);
  };
  const action = useMutation({
    mutationFn: async (body: Record<string, unknown>): Promise<{ singleton?: AgentFileAuditCommand; batch?: AgentFileAuditCommand[] }> => {
      const response = await api.agentAction("file-audit", body);
      if (Array.isArray(body.agents)) return acceptedBatch(body, response);
      const command = acceptedAgentFileAuditCommand(body, response);
      if (!command) throw new Error("file_audit_receipt_unrecognized");
      return { singleton: command };
    },
    onSettled: async (_data, error, body) => {
      await Promise.all([
        client.invalidateQueries({ queryKey: ["admin-agents"] }),
        error ? undefined : client.invalidateQueries({ queryKey: ["setup-status"] }),
        typeof body.agent_id === "string" ? client.invalidateQueries({ queryKey: catalogKey(body.agent_id) }) : undefined,
      ]);
    },
  });

  return <>
    <AgentFileAuditControls agents={agents} busy={action.isPending}
      change={(_, body) => { if (!action.isPending) action.mutate(body); }}
      accepted={action.data?.singleton}
      serverCatalog={{
        agentId, selectAgent, result: catalog.isError || refresh.isError ? undefined : catalog.data,
        loading: catalog.isPending || refresh.isPending, error: catalog.isError || refresh.isError,
        denied: [catalog.error, refresh.error].some((error) => error instanceof ApiResponseError && [401, 403].includes(error.status)),
        refresh: () => {
          if (agentId) {
            if (catalog.isError) void catalog.refetch();
            else refresh.mutate(agentId);
          }
        },
      }}/>
    {action.error ? <p role="alert">{t(action.error instanceof ApiResponseError && [401, 403].includes(action.error.status)
      ? "agents.fileAudit.result.denied" : "agents.actionError")}</p> : null}
    {action.data?.batch?.map((command) => {
      const agent = agents.find((item) => item.id === command.agent_id);
      return <div key={command.command_id}>
        <h3>{agent ? agentHostName(agent) : command.agent_id}</h3>
        <AgentFileAuditReadback accepted={command}/>
      </div>;
    })}
  </>;
}

function acceptedBatch(body: Record<string, unknown>, response: unknown): { batch: AgentFileAuditCommand[]; singleton?: undefined } {
  const targets = body.agents as Array<{ agent_id: string; expected_revision: number }>;
  const config = body.config as { roots: Array<{ collection_scope_id: string }> };
  const items = (response as { items?: unknown } | null)?.items;
  if (!Array.isArray(items) || items.length !== targets.length) throw new Error("file_audit_receipt_unrecognized");
  const batch = targets.map((target) => {
    const item = items.find((row) => row?.agent_id === target.agent_id);
    return acceptedAgentFileAuditCommand({
      ...target,
      command: {
        command_id: item?.command_id, action: body.action, policy_revision: String(target.expected_revision + 1),
        collection_scope_ids: config.roots.map((root) => root.collection_scope_id),
      },
    }, item);
  });
  if (batch.some((command) => !command) || new Set(batch.map((command) => command?.command_id)).size !== targets.length) {
    throw new Error("file_audit_receipt_unrecognized");
  }
  return { batch: batch.filter((command) => command !== null) };
}
