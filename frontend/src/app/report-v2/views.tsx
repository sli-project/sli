import { useTimeZone } from "../../shared/time-zone";
import { useMemo } from "react";
import { Chart, DataTable, TabList, type ResultState } from "../../design-system";
import type { ReactNode } from "react";
import { t } from "../../i18n";
import type { ReportStateDetails, ReportViewDto } from "../../api/report-v2-types";
import { ReportState } from "./ReportState";
import { tableColumns } from "./DetailSection";
import { chartSpecFor } from "./chart-spec";
import { reportEmptyText } from "./empty-copy";

type Row = Record<string, unknown>;

export function ViewTabs({ views }: { views: ReportViewDto[] }) {
  if (views.length < 2) return null;
  return <TabList label={t("reports.views.tabs_aria")}/>;
}

/** A view over a named collection of the result: a table with its own columns or a chart. */
export function CollectionView({ view, rows, reportTitle, emptyDetail, emptyActions, state = "ok", stateDetails, columns: displayColumns }: { view: ReportViewDto; rows: Row[]; reportTitle?: string; emptyDetail?: ReactNode; emptyActions?: ReactNode; state?: ResultState; stateDetails?: ReportStateDetails; columns?: ReturnType<typeof tableColumns> }) {
  const { timeZone } = useTimeZone();
  const columns = useMemo(() => tableColumns(view.columns ?? [], timeZone), [view, timeZone]);
  const spec = useMemo(() => (view.kind === "chart" ? chartSpecFor(view, rows) : null), [view, rows]);
  return <section className="sli-ds-report__views" aria-label={view.title}>
    {!rows.length ? <ReportState state={state === "error" || state === "denied" ? state : "empty"} details={stateDetails}
      detail={state === "ok" || state === "empty" ? <>{reportEmptyText(view, reportTitle ?? view.title ?? view.key)}{emptyDetail}</> : undefined} actions={state === "ok" || state === "empty" ? emptyActions : undefined}/>
      : spec ? <Chart title={view.title ?? ""} spec={spec}/>
      : <DataTable caption={view.title ?? view.key} columns={displayColumns ?? columns} rows={rows} rowKey={(row) => JSON.stringify(row)}/>}
  </section>;
}
