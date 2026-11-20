import { formatNumber } from "../shared/format";
import type { CollectionProgress, CollectorHealthItem, OperationsOverview, RuntimeWorker, SystemHealth } from "../api/client";
import { t, type MessageKey } from "../i18n";
import { ru } from "../i18n/ru";
import { codedText } from "../i18n/event-metadata";
import { formatDateTime } from "../shared/date-time";
import { agentCollectionHeader } from "./agent-collection-view";


export type ReadinessCheck = { label: string; status: "ready" | "warning" | "blocked"; detail: string };
export type ReadinessResult = { status: "ready" | "warning" | "blocked"; label: string; checks: ReadinessCheck[] };

export function operationalCollectionEnabled(collection: OperationsOverview["collection"]) {
  return collection.operational_collection_enabled ?? collection.collection_enabled === true;
}

export function operationalCollectionBlockReason(collection: OperationsOverview["collection"]) {
  return collection.operational_collection_block_reason !== undefined
    ? collection.operational_collection_block_reason
    : collection.collection_block_reason;
}

export function collectionCheckState(item: CollectorHealthItem): string {
  if (item.usage_state === "unused") return "unused";
  if (item.collection_state === "error" || ["failed", "error", "blocked", "timeout", "access_denied", "unavailable"].includes(item.last_status ?? "")) return "error";
  const checked = Date.parse(item.last_successful_collection_utc ?? "");
  if (!Number.isFinite(checked)) return item.collection_state === "stale" ? "stale" : "unknown";
  const ageMinutes = Math.max(0, Math.floor((Date.now() - checked) / 60_000));
  return ageMinutes > 20 ? "stale" : ageMinutes > 5 ? "lagging" : "current";
}

export function collectionBlockReasonLabel(reason?: string | null) {
  if (["windows_event_log_access_denied", "access_denied"].includes(reason ?? "")) return t("operations.actions.logAccessDenied");
  if (reason === "windows_security_context_invalid") return t("operations.actions.securityContextInvalid");
  if (reason?.startsWith("collection_disabled_by_")) return t("operations.readiness_view.check_collection_meaning_disabled");
  if (reason === "timeout") return t("operations.actions.errorTimeout");
  return t("operations.actions.sourceReadFailed");
}

export function collectionOperationalState(data: OperationsOverview) {
  const enabled = operationalCollectionEnabled(data.collection);
  const blockReason = operationalCollectionBlockReason(data.collection);
  const worker = data.workers?.items?.find((item) => item.worker_name === "collection");
  const process = worker ? runtimeWorkerPresentation(worker) : { label: t("operations.actions.notDetermined"), tone: "neutral" as const };
  const checks = data.collector_health.items ?? [];
  const state = !enabled ? blockReason && !blockReason.startsWith("collection_disabled_by_") ? "blocked" : "disabled"
    : checks.some((item) => collectionCheckState(item) === "error") ? "error"
    : checks.some((item) => collectionCheckState(item) === "stale") ? "stale"
    : checks.some((item) => collectionCheckState(item) === "lagging") ? "lagging"
    : checks.length && checks.every((item) => collectionCheckState(item) === "current") ? "current"
    : checks.length ? "unknown"
    : data.collector_health.collection_freshness?.state === "partial" ? "partial"
    : collectionCheckState({ collection_state: data.collector_health.collection_freshness?.state,
      last_successful_collection_utc: data.collector_health.collection_freshness?.checked_at_utc });
  return { state, enabled, blockReason, blockLabel: blockReason ? collectionBlockReasonLabel(blockReason) : t("operations.actions.collectionDisabled"), process };
}

function collectionClocks(item: CollectorHealthItem, timeZone: string) {
  return [
    item.last_successful_collection_utc ? t("operations.actions.lastSuccessfulCheck", { time: formatDateTime(item.last_successful_collection_utc, timeZone) }) : null,
    item.last_event_time_utc ? t("operations.actions.lastEvent", { time: formatDateTime(item.last_event_time_utc, timeZone) }) : null,
  ].filter(Boolean).join(" · ");
}

export function collectionProgressPresentation(progress?: CollectionProgress) {
  if (!progress) return null;
  const total = Number(progress.channels_total ?? 0);
  const reached = Number(progress.boundaries_reached ?? 0);
  const recovery = progress.recovery_items ?? [];
  const items = progress.items ?? [];
  const status = String(progress.status ?? "unknown").toLowerCase();
  const current = progress.check_state === "current" && total > 0 && items.length === total
    && items.every((item) => collectionCheckState(item) === "current");
  const tone: "good" | "warning" | "bad" = status === "completed" && current && total > 0 && reached === total
    ? "good"
    : ["failed", "blocked", "stale"].includes(status) ? "bad" : "warning";
  const value = total > 0 ? t("operations.actions.collectionBoundaryProgress", { reached, total }) : t("operations.actions.boundariesUndefined");
  const detail = recovery.length
    ? t("operations.actions.recoveryPrefix", {
        items: recovery.map((item) => {
          const source = [item.server, item.channel].filter(Boolean).join(" · ") || t("operations.actions.channelUndefined");
          const limit = Number(item.current_limit ?? 0);
          return limit > 0 ? `${source} (${formatNumber(limit)})` : source;
        }).join(", "),
      })
    : reached === total && total > 0 && current
      ? t("operations.actions.boundariesConfirmed")
      : reached > 0 ? t("operations.actions.historicalBoundaries")
      : t("operations.actions.recoveryNotReceived");
  return { value, detail, tone };
}

export function collectionHeaderPresentation(progress?: CollectionProgress, sources: CollectorHealthItem[] = [], timeZone = "browser") {
  if (!progress && !sources.length) return null;
  progress ??= {};
  const channels = progress.items?.length ? progress.items : sources;
  const status = String(progress.status ?? "unknown").toLowerCase();
  const recovery = Number(progress.channels_in_recovery ?? 0);
  const total = Number(progress.channels_total ?? 0);
  const reached = Number(progress.boundaries_reached ?? 0);
  const failed = channels.filter((source) => collectionCheckState(source) === "error");
  const failureDetail = failed.map((source) => [t("operations.actions.sourceFailure", {
    source: [source.server, source.channel].filter(Boolean).join(" · ") || t("operations.actions.channelUndefined"),
    reason: source.failure_reason ? collectionBlockReasonLabel(source.failure_reason) : t(source.last_status === "access_denied" ? "operations.actions.sourceAccessDenied" : "operations.actions.sourceReadFailed"),
  }), progress.blocked_since_utc ? null : t("operations.actions.sourceSinceUnknown"),
    collectionClocks(source, timeZone)].filter(Boolean).join(" · ")).join("; ");
  const oldestChecked = [...channels].filter((item) => Number.isFinite(Date.parse(item.last_successful_collection_utc ?? "")))
    .sort((left, right) => Date.parse(left.last_successful_collection_utc!) - Date.parse(right.last_successful_collection_utc!))[0];
  const knownClocks = oldestChecked ? [channels.length > 1 ? [oldestChecked.server, oldestChecked.channel].filter(Boolean).join(" · ") : null,
    collectionClocks(oldestChecked, timeZone)].filter(Boolean).join(" · ") : "";
  const blockDetail = progress.block_reason ? [collectionBlockReasonLabel(progress.block_reason),
    progress.blocked_since_utc ? t("operations.actions.blockedSince", { time: formatDateTime(progress.blocked_since_utc, timeZone) }) : null,
  ].filter(Boolean).join(" · ") : "";
  const detail = blockDetail ? [blockDetail, failureDetail || knownClocks].filter(Boolean).join(" · ") : failureDetail || (status === "failed" || status === "blocked" ? t("operations.actions.failureDetailsUnknown")
    : recovery > 0 ? t("operations.actions.channelsCatchingUp", { count: recovery })
    : total > 0 && reached === total ? t("operations.actions.boundariesCheckHeader")
      : t("operations.actions.checkingBoundaries"));
  if (failed.length) return { state: "error", title: t("operations.actions.collectionBroken"), detail };
  if (["failed", "blocked"].includes(status)) return { state: "error", title: t("operations.actions.collectionBroken"), detail };
  if (status === "stale" || channels.some((source) => collectionCheckState(source) === "stale")) return { state: "stale", title: t("operations.actions.checkExpired"), detail: knownClocks || t("operations.actions.checkRequired") };
  if (status === "lagging" || channels.some((source) => collectionCheckState(source) === "lagging")) return { state: "lagging", title: t("operations.collectionState.lagging"), detail: knownClocks || t("operations.actions.checkRequired") };
  if (status === "completed" && total > 0 && reached === total && recovery === 0 && channels.length === total && channels.every((source) => collectionCheckState(source) === "current")) return { state: "current", title: t("operations.actions.collectionConfirmed"), detail: knownClocks || detail };
  if (status === "completed" && total > 0 && reached === total) return { state: "unknown", title: t("operations.actions.stateUnknown"), detail: t("operations.actions.checkRequired") };
  if (status === "completed" && total > 0) return { state: "partial", title: t("operations.actions.partialCollection"), detail };
  if (status === "running") return { state: "lagging", title: t("operations.actions.collectionRunning"), detail };
  if (status === "partial") return { state: "partial", title: t("operations.actions.partialCollection"), detail };
  return { state: "unknown", title: t("operations.actions.stateUnknown"), detail };
}

export function collectionChannelPresentation(item: CollectorHealthItem, timeZone = "browser") {
  if (item.usage_state === "unused") return { label: t("operations.sources.unused"), tone: "neutral" as const,
    detail: t("operations.sources.unusedDetail") };
  const check = collectionCheckState(item);
  const boundary = String(item.adaptive_action ?? "").startsWith("exit_recovery:source_boundary_reached");
  const detail = boundary && item.last_successful_collection_utc ? t("operations.actions.boundaryChecked", { time: formatDateTime(item.last_successful_collection_utc, timeZone) }) : undefined;
  if (check === "error") return { label: t("operations.collectionState.error"), tone: "bad" as const, detail };
  if (check === "stale") return { label: t("operations.collectionState.stale"), tone: "bad" as const, detail };
  if (check === "lagging") return { label: t("operations.collectionState.lagging"), tone: "warning" as const, detail };
  if (item.recovery_mode) return { label: t("operations.actions.catchingUp"), tone: "warning" as const };
  if (check === "unknown") return { label: t("operations.actions.checkRequired"), tone: "warning" as const, detail };
  if (boundary) {
    return { label: t("operations.actions.boundaryConfirmed"), tone: "good" as const, detail };
  }
  const severity = String(item.collection_severity ?? "").toLowerCase();
  return {
    label: collectionCheckLabel(item),
    tone: severity === "high" || severity === "failed" || severity === "blocked"
      ? "bad" as const
      : severity === "warn" || severity === "warning" ? "warning" as const : "good" as const,
  };
}

export function runtimeWorkerPresentation(worker: RuntimeWorker) {
  const state = String(worker.state ?? "unknown").toLowerCase();
  const status = String(worker.status ?? "unknown").toLowerCase();
  if (worker.feature_enabled === false || state === "disabled") {
    return { label: t("operations.actions.notEnabled"), tone: "neutral" as const };
  }
  if (state === "stale") return { label: t("operations.actions.heartbeatStale"), tone: "bad" as const };
  if (state === "blocked" || status === "blocked") return { label: t("operations.actions.blocked"), tone: "bad" as const };
  const result = worker.details?.last_result as { failed?: number; detections?: {
    file_ransom_status?: { code?: string; sources?: number };
  } } | undefined;
  const waiting = result?.detections?.file_ransom_status;
  // Only replace the generic cycle-error label when all failed work is this
  // known wait. Stale heartbeat, blocked state and unrelated errors win.
  if (worker.worker_name === "semantic" && status === "failed"
      && waiting?.code === "source_policy_waiting" && Number.isInteger(waiting.sources)
      && (waiting.sources ?? 0) > 0 && result?.failed === waiting.sources) {
    return { label: t("operations.actions.fileRansomPolicyWaiting"), tone: "warning" as const };
  }
  if (status === "failed" || status === "error") return { label: t("operations.actions.cycleError"), tone: "bad" as const };
  if (worker.worker_name === "collection" && status === "partial") {
    return { label: t("operations.actions.partialCollection"), tone: "warning" as const };
  }
  if (status === "partial" || status === "warning") {
    return { label: t("operations.actions.partial"), tone: "warning" as const };
  }
  if (status === "running") return { label: t("operations.actions.running"), tone: "good" as const };
  if (state === "active") return { label: t("operations.actions.active"), tone: "good" as const };
  return { label: t("operations.actions.notDetermined"), tone: "neutral" as const };
}

export function runtimeErrorLabel(value: unknown) {
  const error = String(value ?? "").trim();
  if (!error) return t("operations.actions.errorNone");
  if (/EvtQuery/i.test(error) && /(access denied|отказано в доступе|^\(5,)/i.test(error)) {
    return t("operations.actions.errorEvtQueryDenied");
  }
  if (/EvtNext/i.test(error) && /(access denied|отказано в доступе|^\(5,)/i.test(error)) {
    return t("operations.actions.errorEvtNextDenied");
  }
  if (/timed?\s*out|тайм-аут|превышено время/i.test(error)) {
    return t("operations.actions.errorTimeout");
  }
  return error;
}

function adContextSectionLabels(): Record<string, string> {
  return {
    directory_accounts: t("operations.actions.sectionDirectoryAccounts"),
    privileged_membership: t("operations.actions.sectionPrivilegedMembership"),
    gpo_governance: t("operations.actions.sectionGpoGovernance"),
    vpn_membership: t("operations.actions.sectionVpnMembership"),
  };
}

function runtimeSectionStatusLabel(value: unknown) {
  const status = String(value ?? "").trim().toLowerCase();
  if (status === "complete") return t("operations.actions.sectionStatusComplete");
  if (status === "partial") return t("operations.actions.sectionStatusPartial");
  if (status === "failed") return t("operations.actions.sectionStatusFailed");
  if (status === "skipped") return t("operations.actions.sectionStatusSkipped");
  return status || t("operations.actions.sectionStatusUnknown");
}

export function adContextWorkerSections(worker: RuntimeWorker) {
  if (worker.worker_name !== "ad_context_snapshot") return null;
  const sections = worker.details?.sections;
  if (!sections || typeof sections !== "object" || Array.isArray(sections)) return null;
  const sectionLabels = adContextSectionLabels();
  const entries = Object.entries(sections)
    .filter(([name, value]) => name in sectionLabels && value && typeof value === "object" && !Array.isArray(value))
    .map(([name, value]) => {
      const status = String((value as Record<string, unknown>).status ?? "").trim().toLowerCase();
      return {
        name,
        label: sectionLabels[name],
        status,
        statusLabel: runtimeSectionStatusLabel(status),
      };
    })
    .sort((left, right) => Object.keys(sectionLabels).indexOf(left.name) - Object.keys(sectionLabels).indexOf(right.name));
  if (!entries.length) return null;
  const complete = entries.filter((entry) => entry.status === "complete").length;
  return {
    label: complete === entries.length ? t("operations.actions.allSectionsNormal") : t("operations.actions.sectionsNormal", { complete, total: entries.length }),
    detail: entries.map((entry) => `${entry.label}: ${entry.statusLabel}`).join(" · "),
  };
}

export function postgresOperationalState(postgres: OperationsOverview["postgres"]): ReadinessCheck["status"] {
  const status = String(postgres.status ?? "unknown").toLowerCase();
  const connectivity = String(postgres.connectivity_status ?? "unknown").toLowerCase();
  const metrics = String(postgres.metrics_status ?? "unknown").toLowerCase();
  const available = postgres.available === true
    || connectivity === "ready"
    || (postgres.available === undefined && ["ok", "ready", "warn", "warning", "partial"].includes(status));
  if (!available) return "blocked";
  if (metrics === "partial" || ["warn", "warning", "partial"].includes(status)) return "warning";
  return "ready";
}

export function evaluateOperationsReadiness(operations: OperationsOverview, systemHealth: SystemHealth, timeZone = "browser"): ReadinessResult {
  const agentModel = operations.agent_collection ? agentCollectionHeader(operations.agent_collection, timeZone) : null;
  const agentStatus = agentModel?.state === "error" ? "blocked" : agentModel?.state === "current" ? "ready" : "warning";
  const sloStatus = String(operations.collector_health.operations_slo?.status ?? "unknown").toLowerCase();
  const postgresState = postgresOperationalState(operations.postgres);
  const postgresMetricsPartial = String(operations.postgres.metrics_status ?? "unknown").toLowerCase() === "partial";
  const collectionEnabled = operationalCollectionEnabled(operations.collection);
  const collectionBlockReason = operationalCollectionBlockReason(operations.collection);
  const systemStatus = String(systemHealth.status ?? "unknown").toLowerCase();
  const checks: ReadinessCheck[] = [
    {
      label: "PostgreSQL",
      status: postgresState,
      detail: postgresState === "ready"
        ? t("operations.actions.postgresReady")
        : postgresState === "warning"
          ? postgresMetricsPartial
            ? t("operations.actions.postgresMetricsPartial")
            : t("operations.actions.postgresWarning")
          : t("operations.actions.postgresUnavailable"),
    },
    {
      label: t("operations.actions.checkCollectionContour"),
      status: agentModel ? agentStatus : collectionEnabled ? "ready" : "blocked",
      detail: agentModel ? agentModel.detail : collectionEnabled ? t("operations.actions.collectionRunningAllowed") : String(collectionBlockReason ?? t("operations.actions.collectionDisabled")),
    },
    {
      label: t("operations.actions.checkSecurityFreshness"),
      status: agentModel ? agentStatus : sloStatus === "breached" ? "blocked" : ["ok", "met"].includes(sloStatus) ? "ready" : "warning",
      detail: agentModel ? agentModel.detail : operations.collector_health.operations_slo?.label ?? t("operations.actions.freshnessNotProvided"),
    },
    {
      label: t("operations.actions.checkSystemHealth"),
      status: systemStatus === "ok" ? "ready" : systemStatus === "warn" ? "warning" : "blocked",
      detail: systemHealth.warnings?.join(" · ") || t("operations.actions.systemStatus", { status: systemStatus || "unknown" }),
    },
  ];
  const status = checks.some((item) => item.status === "blocked") ? "blocked" : checks.some((item) => item.status === "warning") ? "warning" : "ready";
  return { status, label: status === "ready" ? t("operations.actions.readinessReady") : status === "warning" ? t("operations.actions.readinessWarning") : t("operations.actions.readinessBlocked"), checks };
}

export function buildOperationsExport(operations: OperationsOverview, exportedAt = new Date().toISOString()) {
  return {
    schema: "ad-log-reports/operations-state/v1",
    exported_at_utc: exportedAt,
    read_only: true,
    operations,
  };
}

export function downloadOperationsExport(operations: OperationsOverview) {
  const document = buildOperationsExport(operations);
  const blob = new Blob([JSON.stringify(document, null, 2)], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = window.document.createElement("a");
  link.href = url;
  link.download = `adlog-operations-${document.exported_at_utc.replace(/[:.]/g, "-")}.json`;
  link.click();
  URL.revokeObjectURL(url);
  return document.exported_at_utc;
}

/** Unknown source states and worker identifiers retain their server presentation. */
export function collectionCheckLabel(item: CollectorHealthItem): string {
  const fallback = item.collection_label || String(item.last_status || t("operations.actions.notDetermined"));
  return item.collection_state ? codedText(`operations.collectionState.${item.collection_state}`, fallback) : fallback;
}

export function eventObservationLabel(item: CollectorHealthItem): string {
  const fallback = item.event_observation_label || item.freshness_label || t("operations.channels.stateUnknown");
  return item.collection_state === "stale" ? codedText("operations.eventObservation.stale", fallback) : fallback;
}

export function workerNameLabel(worker: RuntimeWorker): string {
  const key = `operations.workerName.${worker.worker_name}`;
  return Object.hasOwn(ru, key) ? t(key as MessageKey) : worker.label;
}

export function channelNameLabel(value: string): string {
  const keys = { Security: "operations.channelName.Security", System: "operations.channelName.System", Application: "operations.channelName.Application", ForwardedEvents: "operations.channelName.ForwardedEvents" } as const;
  return Object.hasOwn(keys, value) ? t(keys[value as keyof typeof keys]) : value;
}
