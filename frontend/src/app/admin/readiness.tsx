import { AccessRequestStateView, useAccessRequest } from "../access-request-state";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { api } from "../../api/client";
import { DataTable, MetricStrip, PageHeader, StateView, type MetricItem, type TableColumn } from "../../design-system";
import { formatDateTime } from "../../shared/date-time";
import { useEffectiveAccess, useTimeZone } from "../App";
import { withDomain } from "../domain-navigation";
import { hasAllowedReport } from "../report-access";
import { operationsReadinessView, type ReadinessCheckView, type Tone } from "./readiness-view";
import { Badge } from "./gate";
import { t } from "../../i18n";

const METRIC_TONE: Record<Tone, MetricItem["tone"]> = { neutral: "neutral", accent: "accent", purple: "accent", good: "success", warn: "warning", bad: "danger" };
const BADGE_TONE: Record<Tone, "accent" | "success" | "warning" | "danger" | undefined> = { neutral: undefined, accent: "accent", purple: "accent", good: "success", warn: "warning", bad: "danger" };

/** Готовность и устойчивость проекта: только чтение серверного обзора эксплуатации. */
export function ProjectReadinessPage() {
  const access = useEffectiveAccess();
  const accessRequest = useAccessRequest();
  const { timeZone } = useTimeZone();
  const allowed = hasAllowedReport(access, ["operations.readiness"]);
  const query = useQuery({ queryKey: ["v4", "operations", "readiness"], queryFn: api.platformReadiness, enabled: Boolean(access && allowed && !accessRequest?.error), staleTime: 30_000, retry: false });
  const view = query.data ? operationsReadinessView(query.data, timeZone) : null;
  const scopedAgentHref = (href: string) => href.split(/[?#]/, 1)[0] === "/app/agents"
    ? withDomain(href, window.location.search) : href;
  const columns: TableColumn<ReadinessCheckView>[] = [
    { key: "name", label: t("operations.readiness.check"), render: (row) => row.key?.startsWith("agent:")
      ? <a href={scopedAgentHref(row.href)} title={row.tooltip}>{row.name}</a> : row.name },
    { key: "state", label: t("operations.readiness.state"), render: (row) => <Badge tone={BADGE_TONE[row.tone]}>{row.state}</Badge> },
    { key: "meaning", label: t("operations.readiness.meaning") },
    { key: "nextStep", label: t("operations.readiness.nextStep"), render: (row) => <a href={scopedAgentHref(row.href)} title={row.tooltip}>{row.nextStep}</a> },
  ];
  const generated = query.data?.generated_at_utc ? t("operations.readiness.generatedAt", { time: formatDateTime(query.data.generated_at_utc, timeZone) }) : undefined;

  return <section className="sli-ds-report">
    <PageHeader title={t("operations.readiness.title")}
      subtitle={t("operations.readiness.subtitle")}
      meta={accessRequest?.error ? undefined : generated}/>
    {!access || accessRequest?.error ? <AccessRequestStateView/>
      : !allowed ? <StateView state="denied" detail={<>{t("operations.readiness.denied")} <Link to="/access-user">{t("operations.readiness.openMyAccess")}</Link></>}/>
        : query.isLoading ? <StateView state="loading"/>
          : query.isError ? <StateView state="unavailable" detail={query.error.message} onRetry={() => void query.refetch()}/>
            : view ? <>
              <MetricStrip items={view.metrics.map((metric) => ({ key: metric.label, label: metric.label, value: metric.value, caption: metric.caption, tone: METRIC_TONE[metric.tone] }))}/>
              <h2 className="sli-ds-section-title">{t("operations.readiness.tableTitle")}</h2>
              <p className="sli-ds-header__subtitle">{t("operations.readiness.tableSubtitle")}</p>
              <DataTable columns={columns} rows={view.checks} rowKey={(row) => row.key ?? row.name} caption={t("operations.readiness.tableTitle")}/>
            </> : null}
  </section>;
}

