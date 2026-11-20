import type { SemanticQueueOverview, SemanticQueueStage } from "../../api/client";
import { DataTable, StateView, type TableColumn } from "../../design-system";
import { t } from "../../i18n";
import { formatNumber } from "../../shared/format";
import { Badge } from "./gate";

export function SemanticQueueMetrics({ queues }: { queues?: SemanticQueueOverview }) {
  const thresholds = queues?.warning_thresholds;
  const stages = queues?.stages;
  if (queues?.status !== "ok" || !stages || stages.length !== 3 || !thresholds || queues.window_seconds !== 3600) {
    return <StateView state="unavailable" compact detail={t("operations.semanticMetrics.unavailable")}/>;
  }
  const number = (value: number) => formatNumber(value);
  const age = (row: SemanticQueueStage) => t("operations.semanticMetrics.ageSeconds", { value: number(row.oldest_pending_age_seconds) });
  const columns: TableColumn<SemanticQueueStage>[] = [
    { key: "queue_name", label: t("operations.semanticMetrics.stage"), render: (row) => t(`operations.semanticMetrics.${row.queue_name}`) },
    { key: "depth", label: t("operations.semanticMetrics.depth"), align: "end", render: (row) => row.depth >= thresholds.depth ? <Badge tone="warning">{number(row.depth)}</Badge> : number(row.depth) },
    { key: "oldest_pending_age_seconds", label: t("operations.semanticMetrics.oldest"), render: (row) => row.depth === 0 ? t("operations.semanticMetrics.empty") : row.oldest_pending_age_seconds >= thresholds.oldest_pending_age_seconds ? <Badge tone="warning">{age(row)}</Badge> : age(row) },
    { key: "completed_last_hour", label: t("operations.semanticMetrics.rate"), align: "end", render: (row) => number(row.completed_last_hour) },
  ];
  return <>
    <DataTable columns={columns} rows={stages} rowKey={(row) => row.queue_name} caption={t("operations.semanticMetrics.title")}/>
    <p className="sli-ds-header__subtitle">{t("operations.semanticMetrics.thresholds", { depth: number(thresholds.depth), age: number(thresholds.oldest_pending_age_seconds) })}</p>
  </>;
}
