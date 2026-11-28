import { useQuery } from "@tanstack/react-query";
import { api, type AgentCollectionHealth, type AgentItem } from "../../api/client";

export type AgentObservation = AgentCollectionHealth["items"][number];

export function useAgentSetup(enabled = true) {
  return useQuery({ queryKey: ["setup-status"], queryFn: api.setupStatus,
    enabled, staleTime: 5_000, retry: false, refetchInterval: 30_000 });
}

export function newestAgentTime(times: Array<string | null | undefined>) {
  return times.filter((time): time is string => Number.isFinite(Date.parse(time ?? "")))
    .sort((left, right) => Date.parse(right) - Date.parse(left))[0] ?? null;
}

export function agentAvailability(agent: AgentObservation | AgentItem) {
  if ("connection" in agent) {
    if (agent.state === "disabled") return { state: "disabled" } as const;
    if (agent.connection === "never_seen" || agent.connection === "offline")
      return { state: "offline", since: agent.last_seen } as const;
    const channels = agent.modules.flatMap((module) => module.channels)
      .filter((channel) => channel.state !== "disabled" && channel.state !== "paused");
    const stopped = channels.filter((channel) => channel.state === "error" &&
      (channel.failure_reason === "packet_stale" || channel.failure_reason === "packet_missing"));
    if (stopped.length && stopped.length === channels.length) {
      // Heartbeats measure contact. Only accepted collection packets can clear a delivery outage.
      const lastData = newestAgentTime(stopped.map((channel) => channel.last_packet_at));
      const boundary = lastData ?? newestAgentTime(stopped.map((channel) => channel.issue_since_utc));
      if (!agent.last_packet_at || boundary && Date.parse(agent.last_packet_at) <= Date.parse(boundary))
        return { state: "silent", since: boundary } as const;
    }
    return { state: agent.connection === "online" ? "online" : "unknown" } as const;
  }
  if (agent.status !== "active") return { state: "disabled" } as const;
  const contactAge = Date.now() - Date.parse(agent.last_seen ?? "");
  if (!Number.isFinite(contactAge) || contactAge < 0) return { state: "offline" } as const;
  return contactAge > Math.max(300, (agent.collection_policy?.interval_seconds ?? 60) * 3) * 1000
    ? { state: "offline", since: agent.last_seen } as const : { state: "online" } as const;
}

export function isSilentAgent(agent: AgentObservation | AgentItem) {
  const { state } = agentAvailability(agent);
  return state === "offline" || state === "silent";
}

export function agentObservations(health: AgentCollectionHealth | null | undefined) {
  const byHost = new Map<string, AgentObservation>();
  if (!health || health.state === "unavailable") return byHost;
  for (const agent of health.items) {
    if (agent.state === "disabled") continue;
    const key = agent.host_id || agent.id;
    const previous = byHost.get(key);
    if (!previous || Date.parse(agent.last_seen ?? "1970-01-01") > Date.parse(previous.last_seen ?? "1970-01-01"))
      byHost.set(key, agent);
  }
  return byHost;
}

export function agentCounts(health: AgentCollectionHealth | null | undefined) {
  if (!health || health.state === "unavailable") return null;
  const agents = [...agentObservations(health).values()];
  return { online: agents.filter((agent) => agentAvailability(agent).state === "online").length,
    total: agents.length, silent: agents.filter(isSilentAgent).length };
}
