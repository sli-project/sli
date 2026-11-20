import { EMPTY_VALUE, formatNumber } from "../../shared/format";
import { localizeByteSize } from "../../shared/byte-size";
import { stateTone } from "../../shared/state-tone";
import type { PlatformReadiness } from "../../api/client";
import { postgresOperationalState } from "../operations-actions";
import { agentCollectionDetail, agentCollectionHeader, agentCollectionLabel, agentCollectionName, agentCollectionTooltip, agentCollectionUnregistered } from "../agent-collection-view";
import { t, plural } from "../../i18n";

export type Tone = "neutral" | "accent" | "good" | "warn" | "bad" | "purple";

export type ReadinessMetricView = {
  label: string;
  value: string;
  caption: string;
  icon: string;
  tone: Tone;
};

export type ReadinessCheckView = {
  key?: string;
  name: string;
  state: string;
  tone: Tone;
  meaning: string;
  nextStep: string;
  href: string;
  tooltip?: string;
};

export type OperationsReadinessView = {
  metrics: ReadinessMetricView[];
  checks: ReadinessCheckView[];
};

const text = (value: unknown, fallback = EMPTY_VALUE) => value === null || value === undefined || value === "" ? fallback : String(value);

function runtimeStatus(value: unknown): { label: string; tone: Tone } {
  const normalized = text(value, "unknown").toLocaleLowerCase("ru-RU");
  if (normalized === "disabled") return { label: t("operations.readiness_view.status_disabled"), tone: "neutral" };
  if (normalized === "blocked") return { label: t("operations.metrics.blocked"), tone: "bad" };
  if (normalized === "stale" || normalized === "breach") return { label: t("operations.readiness_view.status_stale"), tone: "bad" };
  const tone = stateTone(value);
  if (tone === "success") return { label: t("operations.readiness_view.status_ok"), tone: "good" };
  if (tone === "warning") return { label: t("operations.readiness_view.status_warn"), tone: "warn" };
  if (tone === "danger") return { label: t("operations.readiness_view.status_error"), tone: "bad" };
  return { label: t("operations.readiness_view.status_undefined"), tone: "neutral" };
}

function warningCountLabel(count: number): string {
  const formattedCount = formatNumber(count);
  return plural(count, {
    one: t("operations.readiness_view.warningCount.one", { count: formattedCount }),
    few: t("operations.readiness_view.warningCount.few", { count: formattedCount }),
    many: t("operations.readiness_view.warningCount.many", { count: formattedCount }),
    other: t("operations.readiness_view.warningCount.other", { count: formattedCount }),
  });
}

export function operationsReadinessView(data: PlatformReadiness, timeZone = "browser"): OperationsReadinessView {
  const workers = data.workers?.items ?? [];
  const activeWorkers = workers.filter((worker) => worker.state === "active" && worker.feature_enabled !== false && !["failed", "error", "blocked", "partial", "warning"].includes(worker.status ?? "")).length;
  const postgresState = postgresOperationalState(data.postgres);
  const postgres = runtimeStatus(postgresState === "ready" ? "ok" : postgresState === "warning" ? "warn" : "failed");
  const storage = runtimeStatus(data.storage.footprint?.snapshot?.stale ? "stale" : data.storage.status ?? data.storage.footprint?.status);
  const collectionModel = agentCollectionHeader(data.agent_collection, timeZone);
  const collection = runtimeStatus(collectionModel.state === "current" ? "ok" : collectionModel.state === "partial" ? "warn" : collectionModel.state);
  const workersState = runtimeStatus(activeWorkers === workers.length && workers.length > 0 ? "ok" : workers.length ? "warn" : "not_registered");
  const postgresWarnings = data.postgres.warnings?.length ?? 0;

  return {
    metrics: [
      {
        label: t("operations.readiness_view.metric_postgres_label"),
        value: postgres.label,
        caption: [localizeByteSize(data.postgres.database?.database_human) ?? t("operations.readiness_view.size_undefined"), postgresWarnings ? warningCountLabel(postgresWarnings) : t("operations.readiness_view.no_warnings")].join(" · "),
        icon: "database",
        tone: postgres.tone,
      },
      {
        label: t("operations.readiness_view.metric_collection_label"),
        value: collection.label,
        caption: collectionModel.detail,
        icon: "history",
        tone: collection.tone,
      },
      {
        label: t("operations.readiness_view.metric_workers_label"),
        value: t("operations.readiness_view.workers_count", { active: activeWorkers, total: workers.length }),
        caption: workers.length ? t("operations.readiness_view.workers_registered") : t("operations.readiness_view.workers_not_registered"),
        icon: "settings",
        tone: workersState.tone,
      },
      {
        label: t("operations.readiness_view.metric_storage_label"),
        value: storage.label,
        caption: localizeByteSize(data.storage.project_overview?.total_human) ?? localizeByteSize(data.storage.project_overview?.database_human) ?? t("operations.readiness_view.volume_undefined"),
        icon: "layers",
        tone: storage.tone,
      },
    ],
    checks: [
      ...(data.archive && data.archive.status !== "ok" ? [{
        key: "archive", name: t("operations.readiness.archive.name"),
        state: t("operations.readiness.archive.unavailable"), tone: "neutral" as const,
        meaning: t(data.archive.status === "invalid_root" ? "operations.readiness.archive.invalidRoot" : "operations.readiness.archive.checkFailed"),
        nextStep: t("operations.actions.checkSystemHealth"), href: "/app/operations#storage-diagnostics",
      }] : []),
      {
        name: t("operations.readiness_view.check_postgres_name"),
        href: "/app/operations?diagnostic=postgres",
        state: postgres.label,
        tone: postgres.tone,
        meaning: postgresState === "blocked"
          ? t("operations.readiness_view.check_postgres_meaning_blocked")
          : t("operations.readiness_view.check_postgres_meaning_ok", { size: localizeByteSize(data.postgres.database?.database_human) ?? t("operations.readiness_view.size_undefined_short"), queries: data.postgres.long_running_queries?.length ?? 0 }),
        nextStep: postgresWarnings ? t("operations.readiness_view.check_postgres_next_warn") : t("operations.readiness_view.next_step_observe"),
      },
      {
        name: t("operations.readiness_view.check_collection_name"),
        href: collectionModel.href,
        state: collectionModel.title,
        tone: collection.tone,
        meaning: collectionModel.detail,
        tooltip: collectionModel.tooltip,
        nextStep: t("operations.agent_collection.open"),
      },
      {
        name: t("operations.readiness_view.check_workers_name"),
        href: "/app/operations#runtime-workers",
        state: workersState.label,
        tone: workersState.tone,
        meaning: t("operations.readiness_view.check_workers_meaning", { active: activeWorkers, total: workers.length }),
        nextStep: activeWorkers === workers.length && workers.length > 0 ? t("operations.readiness_view.next_step_observe") : t("operations.readiness_view.check_workers_next_warn"),
      },
      {
        name: t("operations.readiness_view.check_storage_name"),
        href: "/app/operations#storage-diagnostics",
        state: storage.label,
        tone: storage.tone,
        meaning: t("operations.readiness_view.check_storage_meaning", { volume: localizeByteSize(data.storage.project_overview?.total_human) ?? localizeByteSize(data.storage.project_overview?.database_human) ?? t("operations.readiness_view.size_undefined_short") }),
        nextStep: storage.tone === "good" ? t("operations.readiness_view.next_step_observe") : t("operations.readiness_view.check_storage_next_warn"),
      },
      ...(data.agent_collection?.items ?? []).flatMap((agent) => (agent.domains.length ? agent.domains : [t("operations.agent_collection.no_domain")]).map((domain) => ({ agent, domain })))
        .sort((a, b) => a.domain.localeCompare(b.domain) || a.agent.name.localeCompare(b.agent.name) || a.agent.id.localeCompare(b.agent.id))
        .map(({ agent, domain }) => ({
          key: `agent:${agent.id}:${domain}`,
          name: t("operations.agent_collection.agent", { domain, agent: agentCollectionName(agent) }),
          state: !["paused", "disabled", "current"].includes(agent.state) && agentCollectionUnregistered(agent)
            ? t("operations.agent_collection.not_registered") : agentCollectionLabel(agent.state),
          tooltip: agentCollectionTooltip(agent),
          tone: agent.state === "error" ? "bad" as const : agent.state === "current" ? "good" as const
            : agent.state === "disabled" || agent.state === "paused" || agent.state === "unknown" ? "neutral" as const : "warn" as const,
          meaning: agentCollectionDetail(agent, timeZone), nextStep: t("operations.agent_collection.open"), href: agent.href,
        })),
    ],
  };
}
