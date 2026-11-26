import type { AgentCollectionHealth } from "../api/client";
import { t } from "../i18n";
import { formatDateTime } from "../shared/date-time";

type CollectionAgent = AgentCollectionHealth["items"][number];

export function agentCollectionName(agent: CollectionAgent) {
  return agent.name.trim() || t("operations.agent_collection.no_host");
}

export function agentCollectionUnregistered(agent: CollectionAgent) {
  return !agent.last_seen && !agent.last_packet_at
    && agent.modules.every((module) => module.channels.every((channel) => !channel.last_packet_at && !channel.last_import_at));
}

export function agentCollectionTooltip(agent: CollectionAgent) {
  return t("operations.agent_collection.identifiers", { agent: agent.id, host: agent.host_id });
}

function collectionIssueTime(agent: CollectionAgent, timeZone: string) {
  const errors = agent.modules.flatMap((module) => module.channels.filter((channel) => channel.state === "error"));
  const readErrors = errors.filter((channel) => channel.failure_reason === "read_error");
  // A received error is an observation, not proof of when the outage began.
  const clocks = (readErrors.length ? readErrors.map((channel) => channel.issue_observed_at_utc)
    : errors.map((channel) => channel.issue_since_utc))
    .filter((value): value is string => Boolean(value) && Number.isFinite(Date.parse(value!)))
    .sort((a, b) => Date.parse(a) - Date.parse(b));
  return clocks.length ? t(readErrors.length ? "operations.agent_collection.error_received"
    : "operations.agent_collection.deadline_since", { time: formatDateTime(clocks[0], timeZone) })
    : t("operations.agent_collection.start_unknown");
}

export function agentCollectionHeader(data?: AgentCollectionHealth | null, timeZone = "browser") {
  const failed = data?.items.find((agent) => agent.state === "error");
  const lagging = data?.items.find((agent) => agent.state === "lagging");
  const failedChannels = failed?.modules.flatMap((module) => module.channels.filter((channel) => channel.state === "error")) ?? [];
  const importOverdue = failedChannels.length > 0 && failedChannels.every((channel) => channel.failure_reason === "import_overdue");
  const state = data?.state === "unavailable" ? "unknown" : failed ? "error" : data?.state === "current" ? "current"
    : data?.active_agents ? "partial" : "unknown";
  return {
    state,
    title: t(state === "error" ? "shell.freshness.broken.title" : state === "current" ? "shell.freshness.current.title"
      : state === "partial" ? "shell.freshness.partial.title" : "shell.freshness.unknown.title"),
    detail: [failed ? t(agentCollectionUnregistered(failed) ? "operations.agent_collection.unregistered"
      : importOverdue ? "operations.agent_collection.import_overdue" : "operations.agent_collection.failed", {
      agent: [agentCollectionName(failed), ...(failed.domains.length ? failed.domains : [t("operations.agent_collection.no_domain")])].join(" · "),
    })
      : data?.state === "unavailable" || !data ? t("operations.agent_collection.unavailable")
        : data.diagnostics?.state === "unavailable" ? t("operations.agent_collection.diagnostics_unavailable")
        : lagging ? t("operations.agent_collection.import_pending_named", { agent: agentCollectionName(lagging) })
        : t("operations.agent_collection.count", { current: data.current_agents, total: data.active_agents }),
      failed ? collectionIssueTime(failed, timeZone) : null,
      data?.completeness?.state === "known_gaps" || data?.items.some((agent) => agent.completeness?.state === "known_gaps")
        ? t("operations.agent_collection.accepted_loss") : null,
    ].filter(Boolean).join(" · "),
    href: failed?.href ?? (data?.diagnostics?.state === "unavailable" || data?.state === "unavailable" ? undefined : lagging?.href) ?? "/app/agents",
    tooltip: failed ? agentCollectionTooltip(failed) : lagging && !data?.diagnostics ? agentCollectionTooltip(lagging) : undefined,
  };
}
