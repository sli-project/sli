import type { AgentCollectionHealth, RuntimeWorker, SetupDomain } from "../../api/client";
import { t, type MessageKey } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";
import { EMPTY_VALUE } from "../../shared/format";
import { auditDetectionName } from "./agent-windows-audit";

const modules: Record<string, MessageKey> = {
  "sli.windows.ad-dc": "systemStatus.collect.events",
  "sli.ad-snapshot": "systemStatus.collect.ad",
  "sli.gpo-snapshot": "systemStatus.collect.gpo",
};

const services: Record<string, MessageKey> = {
  ad_snapshot_manifest_coordinator: "systemStatus.service.ad",
  storage_lifecycle: "systemStatus.service.storage",
  post_collection: "systemStatus.service.processing",
  entity_state: "systemStatus.service.entities",
  semantic: "systemStatus.service.detection",
  notification_delivery: "systemStatus.service.notifications",
  core_job_executor_light: "systemStatus.service.light",
  core_job_executor_heavy: "systemStatus.service.heavy",
  core_job_executor_long: "systemStatus.service.long",
};

function missingAudit(agent: AgentCollectionHealth["items"][number]) {
  if (agent.windows_audit?.policy_revision !== agent.policy_revision || ["disabled", "paused"].includes(agent.state)) return [];
  return (agent.windows_audit?.families.domain_controller?.required ?? []).filter((row) =>
    row.success && row.actual_success === false || row.failure && row.actual_failure === false);
}

export function statusAuditChecks(health: AgentCollectionHealth | null | undefined, domains: SetupDomain[]) {
  const archived = new Set(domains.filter((domain) => domain.is_archived).map((domain) => domain.fqdn.toLowerCase()));
  return (health?.items ?? []).filter((agent) => !agent.domains.length || !agent.domains.every((domain) => archived.has(domain.toLowerCase())))
    .flatMap((agent) => {
      const missing = missingAudit(agent);
      const checks = new Set(missing.flatMap((row) => [...(row.detections ?? []).map(String), ...(row.domain_changes ? ["domain"] : [])]));
      const name = agent.name.trim().slice(0, 200) || EMPTY_VALUE;
      return [...checks].map((check) => ({ id: `${agent.id}:${check}`, name,
        check: check === "domain" ? t("agents.auditDomainChanges") : auditDetectionName(Number(check)),
        action: t("systemStatus.auditEnable", { name }), href: `/app/agents?agent_id=${encodeURIComponent(agent.id)}` }));
    });
}

export function statusSources(health: AgentCollectionHealth | null | undefined, domains: SetupDomain[], timeZone: string) {
  const archived = new Set(domains.filter((domain) => domain.is_archived).map((domain) => domain.fqdn.toLowerCase()));
  return (health?.items ?? []).filter((agent) => !agent.domains.length || !agent.domains.every((domain) => archived.has(domain.toLowerCase())))
    .flatMap((agent) => {
      const collected = agent.modules.filter((module) => Object.hasOwn(modules, module.module_id));
      // Agents assigned only to hidden modules do not belong to this page.
      if (agent.modules.length && !collected.length) return [];
      const channels = collected.flatMap((module) => module.channels);
      const active = channels.filter((channel) => !["disabled", "paused"].includes(channel.state));
      const rejected = active.find((channel) => channel.import_failure_reason);
      const packetTimes = channels.map((channel) => channel.last_packet_at).filter((value): value is string => Boolean(value) && Number.isFinite(Date.parse(value!)));
      const lastData = packetTimes.sort((a, b) => Date.parse(b) - Date.parse(a))[0] ?? null;
      const name = agent.name.trim().slice(0, 200) || EMPTY_VALUE;
      const auditCount = missingAudit(agent).length;
      const time = formatDateTime(lastData, timeZone, { withYear: false });
      // A stream the server expects but that never reported: the deadline time is its own, not another channel's packet.
      const missing = active.find((channel) => channel.channel && !channel.last_packet_at && channel.state === "error"
        && channel.failure_reason === "packet_missing" && Number.isFinite(Date.parse(channel.issue_since_utc ?? "")));
      let state: MessageKey = "systemStatus.source.receiving";
      let action: MessageKey | null = null;
      let tone = "current";
      if (agent.state === "disabled" || agent.state === "paused" || (channels.length > 0 && !active.length)) {
        state = "systemStatus.source.paused"; action = "systemStatus.action.enable"; tone = "neutral";
      } else if (rejected) {
        state = rejected.import_failure_reason === "short_event_attestation_failed" ? "systemStatus.source.originRejected"
          : rejected.import_failure_reason === "short_event_summary_conflict" ? "systemStatus.source.summaryRejected"
          : "systemStatus.source.eventRejected";
        tone = "neutral";
      } else if (active.some((channel) => channel.failure_reason === "read_error")) {
        state = "systemStatus.source.readError"; action = "systemStatus.action.permissions"; tone = "error";
      } else if (active.some((channel) => channel.failure_reason === "import_overdue")) {
        state = "systemStatus.source.importError"; action = "systemStatus.action.import"; tone = "error";
      } else if (agent.connection === "offline") {
        state = "systemStatus.source.offline"; action = "systemStatus.action.agent"; tone = "error";
      } else if (missing) {
        state = "systemStatus.source.channelSilent"; action = "systemStatus.action.agent"; tone = "error";
      } else if (!lastData) {
        state = "systemStatus.source.waiting"; action = "systemStatus.action.agent"; tone = "neutral";
      } else if (active.some((channel) => ["unknown", "waiting"].includes(channel.state))) {
        state = "systemStatus.source.check"; action = "systemStatus.action.agent"; tone = "neutral";
      } else if (active.some((channel) => ["error", "lagging"].includes(channel.state))) {
        state = "systemStatus.source.silent"; action = "systemStatus.action.agent"; tone = "error";
      } else if (agent.connection !== "online" || !active.length) {
        state = "systemStatus.source.check"; action = "systemStatus.action.agent"; tone = "neutral";
      } else if (auditCount > 0) {
        state = "agents.auditOffStatus"; action = "systemStatus.auditEnable"; tone = "neutral";
      }
      return [{ id: agent.id, name, lastData, time, tone: agent.delivery_fallback ? "error" : tone, connected: Boolean(agent.last_seen),
        collection: collected.map((module) => t(modules[module.module_id])).join(", ") || EMPTY_VALUE,
        state: agent.delivery_fallback ? t("agents.deliveryFallback", { name, version: agent.agent_version || EMPTY_VALUE, since: formatDateTime(agent.delivery_fallback.since, timeZone, { withYear: false }), until: formatDateTime(agent.delivery_fallback.last_packet_at, timeZone, { withYear: false }) }) : t(state, { name, count: auditCount, channel: missing?.channel ?? "", time: state === "systemStatus.source.offline" ? formatDateTime(agent.last_seen, timeZone, { withYear: false })
          : state === "systemStatus.source.silent" ? formatDateTime(active.filter((channel) => ["error", "lagging"].includes(channel.state)).map((channel) => channel.last_packet_at).filter((value): value is string => Number.isFinite(Date.parse(value ?? ""))).sort((a, b) => Date.parse(b) - Date.parse(a))[0] ?? lastData, timeZone, { withYear: false })
          : rejected ? formatDateTime(rejected.import_failure_at, timeZone, { withYear: false })
          : state === "systemStatus.source.channelSilent" ? formatDateTime(missing?.issue_since_utc, timeZone, { withYear: false }) : time }),
        fallback: agent.delivery_fallback, currentAgent: agent.id,
        action: action ? t(action, { name }) : EMPTY_VALUE,
      }];
    });
}

export function statusServices(workers: RuntimeWorker[], timeZone: string) {
  return workers.filter((worker) => Object.hasOwn(services, worker.worker_name)).map((worker) => {
    const stopped = worker.feature_enabled === false || worker.state === "disabled";
    const running = !stopped && worker.state === "active" && !["failed", "error", "blocked", "partial", "warning", "stopped"].includes(worker.status ?? "");
    const unobserved = worker.state === "unknown" || worker.state === "not_registered";
    return { id: worker.worker_name, name: t(services[worker.worker_name]),
      state: t(running ? "systemStatus.service.running" : stopped ? "systemStatus.service.disabled" : unobserved ? "systemStatus.service.check" : "systemStatus.service.failed"),
      tone: running ? "current" : stopped || unobserved ? "neutral" : "error",
      started: formatDateTime(worker.started_at, timeZone, { withYear: false }),
    };
  });
}
