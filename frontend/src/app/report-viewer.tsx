import { EMPTY_VALUE } from "../shared/format";
import { useDateFormatters } from "../design-system/useDateFormatters";
import { useMemo } from "react";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { api, type V4ReportData } from "../api/client";
import { DataTable, MetricStrip, PageHeader, StateView, type MetricItem, type ResultState, type TableColumn } from "../design-system";
import { useOverlays } from "../design-system";
import { t } from "../i18n";
import { reportSupportsPreference } from "./report-labels";

const FIELD_LABELS: Record<string, string> = {
  get display_name() { return t("reports.viewer.field.display_name"); },
  get enabled() { return t("reports.viewer.field.enabled"); },
  get locked() { return t("reports.viewer.field.locked"); },
  get record_key() { return t("reports.viewer.field.record_key"); },
  get relation_type() { return t("reports.viewer.field.relation_type"); },
  get sam_account_name() { return t("reports.viewer.field.sam_account_name"); },
  get distinguished_name() { return t("reports.viewer.field.distinguished_name"); },
  get object_sid() { return t("reports.viewer.field.object_sid"); },
  get object_guid() { return t("reports.viewer.field.object_guid"); },
  get description() { return t("reports.viewer.field.description"); },
  get department() { return t("reports.viewer.field.department"); },
  get title() { return t("reports.viewer.field.title"); },
  get mail() { return t("reports.viewer.field.mail"); },
  get member_of() { return t("reports.viewer.field.member_of"); },
  get source_section() { return t("reports.viewer.field.source_section"); },
};

const PAGE_SIZE = 50;

type Row = Record<string, unknown>;

export function formatValue(value: unknown): string {
  if (value === null || value === undefined || value === "") return EMPTY_VALUE;
  if (typeof value === "boolean") return value ? t("reports.viewer.value.yes") : t("reports.viewer.value.no");
  if (Array.isArray(value)) return value.length ? value.map(formatValue).join(", ") : EMPTY_VALUE;
  if (typeof value === "object") return Object.entries(value as Record<string, unknown>).map(([key, item]) => `${FIELD_LABELS[key] ?? key}: ${formatValue(item)}`).join(" · ");
  return String(value);
}

const isTimeField = (key: string) => /(_utc|observed_at)$/.test(key);

/** Явное состояние выдачи сервера: `gated` и прочие неизвестные значения не выдаются за пустой результат. */
export function viewerState(data: V4ReportData | undefined, rowCount: number): ResultState {
  if (!data) return "loading";
  if (data.state === "gated") return "unavailable";
  if (data.state === "denied") return "denied";
  if (data.state === "partial" || data.state === "stale") return rowCount ? data.state : "unavailable";
  return rowCount ? "ok" : "empty";
}

function summaryMetrics(summary: NonNullable<V4ReportData["summary"]>): MetricItem[] {
  const items: MetricItem[] = [];
  if (typeof summary.total_objects === "number") {
    items.push({
      key: "total_objects", label: t("reports.viewer.metric.total_objects"), value: summary.total_objects,
      caption: summary.by_entity_type?.length ? summary.by_entity_type.map((item) => `${item.entity_type}: ${item.count}`).join(" · ") : undefined,
    });
  }
  if (typeof summary.without_observation_count === "number") {
    items.push({ key: "without_observation", label: t("reports.viewer.metric.without_observation"), value: summary.without_observation_count, tone: "warning" });
  }
  if (typeof summary.total_relations === "number") items.push({ key: "total_relations", label: t("reports.viewer.metric.total_relations"), value: summary.total_relations });
  return items;
}

/** Просмотр опубликованного отчёта v4 по ключу: таблица разрешённых полей, постраничная подгрузка и экспорт при разрешении. */
export function ReportViewerPage() {
  const { formatCell } = useDateFormatters();
  const params = useParams({ strict: false }) as { reportKey?: string };
  const reportKey = params.reportKey ? decodeURIComponent(params.reportKey) : "";
  const client = useQueryClient();
  const { toast } = useOverlays();
  const query = useInfiniteQuery({
    queryKey: ["v4", "report", reportKey],
    queryFn: ({ pageParam }) => {
      const filters = new URLSearchParams();
      if (pageParam) filters.set("cursor", pageParam);
      return api.v4ReportData(reportKey, PAGE_SIZE, filters);
    },
    initialPageParam: "",
    getNextPageParam: (last) => (last.has_more && last.next_cursor ? last.next_cursor : undefined),
    enabled: Boolean(reportKey),
    retry: false,
  });
  const preference = useMutation({
    mutationFn: (pinned: boolean) => api.v4UpdateReportPreference(reportKey, pinned),
    onSuccess: async (_result, pinned) => {
      await Promise.all([
        client.invalidateQueries({ queryKey: ["v4", "report", reportKey] }),
        client.invalidateQueries({ queryKey: ["v4", "reports"] }),
        client.invalidateQueries({ queryKey: ["v4", "workspace"] }),
        client.invalidateQueries({ queryKey: ["v4", "access"] }),
      ]);
      toast(pinned ? t("reports.toast.pinned") : t("reports.toast.unpinned"), t("reports.toast.home_updated"));
    },
    onError: (error: Error) => toast(t("reports.toast.pin_failed"), error.message),
  });

  const first = query.data?.pages[0];
  const rows = useMemo<Row[]>(() => query.data?.pages.flatMap((page) => page.items) ?? [], [query.data]);
  const rowIndex = useMemo(() => new Map(rows.map((row, index) => [row, index])), [rows]);
  const columns = useMemo<TableColumn<Row>[]>(() => {
    const visible = first?.grant_branch_fields;
    return (first?.fields ?? []).filter((field) => !visible || visible.includes(field.key)).map((field) => ({
      key: field.key, label: field.label,
      render: (row: Row) => (isTimeField(field.key) && row[field.key] ? formatCell(row[field.key], "datetime") : formatValue(row[field.key])),
    }));
  }, [first, formatCell]);

  const denied = query.error && /403|report_access_denied|forbidden/.test(query.error.message);
  const title = first?.report.name ?? t("reports.viewer.title.fallback");
  const state: ResultState = denied ? "denied" : query.error ? "unavailable" : query.isLoading ? "loading" : viewerState(first, rows.length);
  const report = first?.report;
  const canExport = Boolean(report?.allowed_actions.includes("export"));
  const actions = report ? <>
    {reportSupportsPreference(report)
      ? <button type="button" className="sli-ds-button" disabled={preference.isPending} onClick={() => preference.mutate(!report.pinned)}>{preference.isPending ? t("reports.viewer.action.saving") : report.pinned ? t("reports.viewer.action.unpin") : t("reports.viewer.action.pin")}</button>
      : null}
    {canExport ? <a className="sli-ds-button" href={api.v4ReportExportUrl(reportKey)}>{t("reports.viewer.action.export")}</a> : null}
  </> : null;
  const metrics = first?.summary ? summaryMetrics(first.summary) : [];
  const limit = first?.limits && typeof first.limits.limit === "number" ? first.limits.limit : null;

  return <section className="sli-ds-report">
    <PageHeader
      title={denied ? t("reports.viewer.denied.title") : title}
      subtitle={report?.purpose ?? (denied ? undefined : t("reports.viewer.subtitle"))}
      meta={reportKey}
      actions={actions}/>
    {denied ? <StateView state="denied" detail={<>{t("reports.viewer.denied.text_before")}<Link to="/reports">{t("reports.viewer.denied.catalog_link")}</Link>{t("reports.viewer.denied.text_after")}</>}/> : null}
    {!denied && state !== "ok" && state !== "partial" && state !== "stale" ? <StateView state={state}
      detail={query.error?.message ?? (first?.state === "gated" ? t("reports.viewer.error.gated") : state === "empty" ? t("reports.viewer.error.empty") : undefined)}
      onRetry={() => void query.refetch()}/> : null}
    {!denied && (state === "partial" || state === "stale") ? <StateView state={state} compact/> : null}
    {metrics.length ? <MetricStrip items={metrics}/> : null}
    {!denied && rows.length ? <DataTable caption={title} columns={columns} rows={rows} rowKey={(row) => String(rowIndex.get(row))}
      hasMore={query.hasNextPage} loadingMore={query.isFetchingNextPage} onLoadMore={() => void query.fetchNextPage()}/> : null}
    {first ? <p className="sli-ds-header__subtitle">{t("reports.viewer.footer", { dataset_key: first.dataset_key, dataset_version: first.report.dataset_version, limit_clause: limit ? t("reports.viewer.footer_limit", { limit }) : "" })}</p> : null}
  </section>;
}
