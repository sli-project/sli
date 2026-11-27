import type { AgentCollectionHealth, PasswordDetectionStatus, RuntimeWorker, SetupDomain } from "../../api/client";
import { t, type MessageKey } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";
import { EMPTY_VALUE } from "../../shared/format";
import { auditDetectionName } from "./agent-windows-audit";
import { collectionDiagnosis, missingAuditSetting } from "./collection-diagnosis";

const modules: Record<string, MessageKey> = {
  "sli.windows.ad-dc": "systemStatus.collect.events",
  "sli.ad-snapshot": "systemStatus.collect.ad",
  "sli.gpo-snapshot": "systemStatus.collect.gpo",
};

const gapMessages: Record<string, MessageKey> = {
  "sli.heartbeat": "systemStatus.dataGap.heartbeat",
  "sli.windows.ad-dc": "systemStatus.dataGap.events",
  "sli.windows.ad-dc-history": "systemStatus.dataGap.events",
  "sli.ad-snapshot": "systemStatus.dataGap.ad",
  "sli.gpo-snapshot": "systemStatus.dataGap.gpo",
};

export function statusSourceGaps(health: AgentCollectionHealth | null | undefined, timeZone: string) {
  return [...new Map((health?.items ?? []).flatMap((agent) => (agent.data_gaps ?? []).map((gap) => {
    const message = gap.module_id && Object.hasOwn(gapMessages, gap.module_id) ? gapMessages[gap.module_id] : "systemStatus.dataGap";
    const id = [agent.id, message, gap.from_utc, gap.to_utc].join(":");
    const text = t(message, {
      computer: agent.name.trim().slice(0, 200) || EMPTY_VALUE,
      from: formatDateTime(gap.from_utc, timeZone),
      to: formatDateTime(gap.to_utc, timeZone),
    });
    return [id, text] as const;
  }))).entries()];
}

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

const adDcImportIssues: Record<string, MessageKey> = {
  agent_ad_dc_catalog_unavailable: "systemStatus.adDcImport.catalog",
  agent_ad_dc_storage_connection_unconfigured: "systemStatus.adDcImport.connection",
  agent_ad_dc_storage_authorization_missing: "systemStatus.adDcImport.authorizationMissing",
  agent_ad_dc_storage_authorization_invalid: "systemStatus.adDcImport.authorizationInvalid",
  agent_ad_dc_storage_access_denied: "systemStatus.adDcImport.accessDenied",
};

export function statusAdDcImportIssue(workers: RuntimeWorker[]) {
  const issue = workers.find((worker) => worker.worker_name === "post_collection")?.details?.ad_dc_import_issue;
  return typeof issue === "string" && Object.hasOwn(adDcImportIssues, issue) ? t(adDcImportIssues[issue]) : null;
}

function missingAudit(agent: AgentCollectionHealth["items"][number]) {
  if (agent.windows_audit?.policy_revision !== agent.policy_revision || ["disabled", "paused"].includes(agent.state)) return [];
  return (agent.windows_audit?.families.domain_controller?.required ?? []).filter(missingAuditSetting);
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
      const diagnosis = agent.connection === "online" && active.length
        ? collectionDiagnosis(agent, timeZone, agent.collection_interval_seconds)
        : null;
      const time = formatDateTime(lastData, timeZone, { withYear: false });
      // A stream the server expects but that never reported: the deadline time is its own, not another channel's packet.
      const missing = active.find((channel) => channel.channel && !channel.last_packet_at && channel.state === "error"
        && channel.failure_reason === "packet_missing" && Number.isFinite(Date.parse(channel.issue_since_utc ?? "")));
      const stalePacket = active.filter((channel) => channel.failure_reason === "packet_stale")
        .map((channel) => channel.last_packet_at)
        .filter((value): value is string => Number.isFinite(Date.parse(value ?? "")))
        .sort((a, b) => Date.parse(b) - Date.parse(a))[0];
      const readError = active.find((channel) => channel.failure_reason === "read_error");
      const importError = active.find((channel) => channel.failure_reason === "import_overdue");
      let state: MessageKey = "systemStatus.source.receiving";
      let action: MessageKey | null = null;
      if (agent.state === "disabled" || agent.state === "paused" || (channels.length > 0 && !active.length)) {
        state = "systemStatus.source.paused"; action = "systemStatus.action.enable";
      } else if (rejected) {
        state = rejected.import_failure_reason === "short_event_attestation_failed" ? "systemStatus.source.originRejected"
          : rejected.import_failure_reason === "short_event_summary_conflict" ? "systemStatus.source.summaryRejected"
          : "systemStatus.source.eventRejected";
      } else if (agent.connection === "offline") {
        state = "systemStatus.source.offline"; action = "systemStatus.action.agent";
      } else if (agent.connection === "never_seen") {
        state = "systemStatus.source.notConnected"; action = "systemStatus.action.agent";
      } else if (!diagnosis) {
        if (readError) state = "systemStatus.source.readError";
        else if (importError) state = "systemStatus.source.importError";
        else if (missing) state = "systemStatus.source.channelSilent";
        else if (!lastData) state = "systemStatus.source.waiting";
        else if (stalePacket) state = "systemStatus.source.silent";
        else if (active.some((channel) => ["error", "unknown", "waiting"].includes(channel.state)) || agent.connection !== "online" || !active.length)
          state = "systemStatus.source.check";
        if (state !== "systemStatus.source.receiving")
          action = state === "systemStatus.source.importError" ? "systemStatus.action.import" : "systemStatus.action.agent";
      }
      const direct = state === "systemStatus.source.receiving" ? diagnosis : null;
      const observedAt = state === "systemStatus.source.readError" ? readError?.issue_observed_at_utc
        : state === "systemStatus.source.importError" ? importError?.issue_since_utc : null;
      const observation = observedAt
        ? ` · ${formatDateTime(observedAt, timeZone, { withYear: false })}` : "";
      return [{ id: agent.id, name, lastData, time, connected: Boolean(agent.last_seen),
        href: state !== "systemStatus.source.receiving" || direct || agent.delivery_fallback ? `/app/agents?agent_id=${encodeURIComponent(agent.id)}` : null,
        collection: collected.map((module) => t(modules[module.module_id])).join(", ") || EMPTY_VALUE,
        state: agent.delivery_fallback ? t("agents.deliveryFallback", { name, version: agent.agent_version || EMPTY_VALUE, since: formatDateTime(agent.delivery_fallback.since, timeZone, { withYear: false }), until: formatDateTime(agent.delivery_fallback.last_packet_at, timeZone, { withYear: false }) }) : direct?.state ?? t(state, { name, channel: missing?.channel ?? "", time: state === "systemStatus.source.offline" ? formatDateTime(agent.last_seen, timeZone, { withYear: false })
          : state === "systemStatus.source.silent" ? formatDateTime(stalePacket, timeZone, { withYear: false })
          : rejected ? formatDateTime(rejected.import_failure_at, timeZone, { withYear: false })
          : state === "systemStatus.source.channelSilent" ? formatDateTime(missing?.issue_since_utc, timeZone, { withYear: false }) : time }) + observation,
        fallback: agent.delivery_fallback, currentAgent: agent.id,
        action: direct?.action ?? (action ? t(action, { name }) : EMPTY_VALUE),
      }];
    });
}

const passwordRules: Record<PasswordDetectionStatus["items"][number]["rule_id"], MessageKey> = {
  "qw.password-brute-force": "security.problems.presentation.qw.password-brute-force.title",
  "qw.password-spray": "security.problems.presentation.qw.password-spray.title",
};

const passwordStates: Record<PasswordDetectionStatus["items"][number]["state"], MessageKey> = {
  failed: "systemStatus.passwordDetection.failed",
  stalled: "systemStatus.passwordDetection.stalled",
  behind: "systemStatus.passwordDetection.behind",
  catching_up: "systemStatus.passwordDetection.catchingUp",
  history_pending: "systemStatus.passwordDetection.historyPending",
  recovered: "systemStatus.passwordDetection.recovered",
  current: "systemStatus.passwordDetection.current",
  quiet: "systemStatus.passwordDetection.quiet",
  unknown: "systemStatus.passwordDetection.unknown",
  disabled: "systemStatus.service.disabled",
};

export function statusPasswordRules(status: PasswordDetectionStatus | undefined, timeZone: string) {
  if (status?.status !== "ok") return [];
  return status.items.filter(({ rule_id, state }) => Object.hasOwn(passwordRules, rule_id) && Object.hasOwn(passwordStates, state))
    .map(({ rule_id, state, observed_at }) => ({
      id: rule_id, name: t(passwordRules[rule_id]), state: t(passwordStates[state]),
      tone: state === "failed" || state === "stalled" ? "error" : ["current", "quiet", "recovered"].includes(state) ? "current" : "neutral",
      observed: formatDateTime(observed_at, timeZone, { withYear: false, seconds: true }),
    }));
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
