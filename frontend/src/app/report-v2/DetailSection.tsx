import { EMPTY_VALUE } from "../../shared/format";
import { useTimeZone } from "../../shared/time-zone";
import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { ACTION_COMPONENTS, CELL_COMPONENTS, ROW_COMPONENTS } from "./custom";
import { useInfiniteQuery } from "@tanstack/react-query";
import { DataTable, formatCell, StateView, type TableColumn } from "../../design-system";
import { t } from "../../i18n";
import { api, ApiResponseError } from "../../api/client";
import type { ReportColumnDto, ReportDefinitionDto, ReportDetailDto, ReportResultDto } from "../../api/report-v2-types";
import { withReturnTo } from "./legacy";
import { columnValue, fillTemplate, readPath } from "./state";
import { accessErrorReason, accessReason } from "./access";
import { ReportState } from "./ReportState";

type Row = Record<string, unknown>;
const rowKey = (row: Row) => row.storage_kind === "file_audit_snapshot" ? String(row.evidence_key) : JSON.stringify(row);

export const cellKind = (column: ReportColumnDto) => (column.kind === "state" || column.kind === "code" ? "text" : column.kind);

/** Window of the current result, for cell components that lay out days. */
export const ResultWindowContext = createContext<ReportResultDto["window"] | undefined>(undefined);

export function CellComponent({ name, row }: { name: string; row: Row }) {
  const window = useContext(ResultWindowContext);
  const Cell = CELL_COMPONENTS[name];
  return Cell ? <Cell row={row} window={window}/> : null;
}

/** Table columns from a declaration, with link templates, return_to and cell components. */
export function tableColumns(columns: ReportColumnDto[], timeZone?: string): TableColumn<Row>[] {
  return columns.map((column) => ({
    key: column.key,
    label: column.label,
    kind: cellKind(column),
    sortable: column.sortable,
    hiddenByDefault: column.hidden_by_default,
    value: (row) => columnValue(column, row),
    render: column.component ? (row) => <CellComponent name={column.component!} row={row}/> : column.link ? (row) => {
      const text = formatCell(columnValue(column, row), cellKind(column), timeZone);
      const href = fillTemplate(column.link!, row);
      return href ? <a href={withReturnTo(href, `${window.location.pathname}${window.location.search}`)} onClick={(event) => event.stopPropagation()}>{text}</a> : text;
    } : undefined,
  }));
}

/** Plain-text summary of a row for the clipboard (the "copy fact" action). */
export function rowFactsText(title: string, columns: ReportColumnDto[], row: Row, timeZone?: string): string {
  return [title, ...columns.filter((column) => !column.component).map((column) => `• ${column.label}: ${formatCell(columnValue(column, row), cellKind(column), timeZone)}`)].join("\n");
}

export function CopyFactsButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  if (typeof navigator === "undefined" || !navigator.clipboard?.writeText) return null;
  return <button type="button" className="sli-ds-button" onClick={() => { void navigator.clipboard.writeText(text).then(() => setCopied(true)); }}>
    {copied ? t("reports.detail.copied") : t("reports.detail.copy")}
  </button>;
}

/** Drill-down table for one row (ADR 0010 Detail). */
export function DetailSection({ definition, detail, row, baseParams }: {
  definition: ReportDefinitionDto;
  detail: ReportDetailDto;
  row: Row;
  baseParams: string;
}) {
  const { timeZone } = useTimeZone();
  const rowId = String(readPath(row, detail.key) ?? "");
  const query = useInfiniteQuery({
    queryKey: ["report-v2", "detail", definition.key, rowId, baseParams],
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams(baseParams);
      params.delete("cursor");
      if (pageParam) params.set("cursor", pageParam);
      return api.reportV2Detail(definition.key, rowId, params);
    },
    initialPageParam: null as string | null,
    getNextPageParam: (page: ReportResultDto) => (page.has_more ? page.next_cursor : null),
    enabled: Boolean(rowId) && detail.kind === "sub" && detail.access?.allowed !== false,
    retry: false,
  });
  const inlineRows = detail.kind === "inline" && detail.inline ? ((readPath(row, detail.inline) as Row[] | undefined) ?? []) : null;
  const rows = useMemo(() => inlineRows ?? query.data?.pages.flatMap((page) => page.items as Row[]) ?? [], [inlineRows, query.data]);
  const gpoReport = definition.key === "ad.gpo.v2";
  const declaredColumns = useMemo(() => tableColumns(gpoReport ? detail.columns.filter((column) => column.key !== "limitation") : detail.columns, timeZone), [detail, gpoReport, timeZone]);
  const first = query.data?.pages[0];
  const latest = query.data?.pages.at(-1);
  const deniedError = query.error instanceof ApiResponseError && [401, 403].includes(query.error.status) ? query.error : null;
  const selectionScope = JSON.stringify([definition.key, rowId, baseParams, detail.kind, detail.inline,
    detail.row_component, detail.access, first?.access, Boolean(deniedError), first?.state === "denied"]);
  const [selection, setSelection] = useState<{ scope: string; key: string } | null>(null);
  const chosen = selection?.scope === selectionScope ? rows.find((item) => rowKey(item) === selection.key) ?? null : null;
  // Resolve from current rows on every render, then discard keys absent from this population.
  useEffect(() => { if (selection && !chosen) setSelection(null); }, [selection, chosen]);
  const choose = (item: Row) => setSelection({ scope: selectionScope, key: rowKey(item) });
  const RowComponent = detail.row_component ? ROW_COMPONENTS[detail.row_component] : undefined;
  const pick = RowComponent ? choose : undefined;
  const Actions = detail.actions ? ACTION_COMPONENTS[detail.actions] : undefined;
  const problemEvidence = definition.key === "security.problems" && detail.kind === "sub";
  const total = problemEvidence ? latest?.filtered_count : first?.filtered_count;
  const lowerBound = Math.max(latest?.coverage.evidence_total_lower_bound ?? 0, rows.length + (query.hasNextPage ? 1 : 0));
  const missingSources = problemEvidence ? rows.filter((item) => item.storage_kind === "file_audit_snapshot"
    ? item.availability === "unavailable" : item.event_db_id == null).length : 0;
  const hasNativeSnapshots = problemEvidence && rows.some((item) => item.storage_kind === "file_audit_snapshot");
  const columns = problemEvidence ? declaredColumns.map((column, index) => ({ ...column,
    label: index === 0 && hasNativeSnapshots ? detail.title : column.label,
    render: (item: Row) => item.storage_kind === "file_audit_snapshot"
      ? index === 0 ? <button type="button" className="sli-ds-button" onClick={(event) => { event.stopPropagation(); choose(item); }}>{t("evidence.acl.snapshot")}</button> : EMPTY_VALUE
      : column.render ? column.render(item) : formatCell(column.value?.(item), column.kind, timeZone),
  })) : declaredColumns;
  const emptyDetail = problemEvidence ? t("security.problems.evidence.empty") : t("reports.empty.detail", { detail: detail.title, report: definition.title });

  if (detail.access?.allowed === false || deniedError) return <section aria-label={detail.title} className="sli-ds-report__views">
    <h3 style={{ margin: 0 }}>{detail.title}</h3>
    <ReportState state="denied" detail={deniedError ? accessErrorReason(deniedError) : accessReason(detail.access)}/>
  </section>;

  return <section aria-label={detail.title} className="sli-ds-report__views">
    <h3 style={{ margin: 0 }}>{detail.title}</h3>
    {inlineRows ? (inlineRows.length ? <DataTable caption={detail.title} columns={columns} rows={inlineRows} rowKey={rowKey} onRowClick={pick} selectedKey={chosen ? rowKey(chosen) : null}/> : <ReportState state="empty" detail={emptyDetail}/>)
      : query.isLoading ? <StateView state="loading"/>
      : query.error && !rows.length ? <ReportState state="error" onRetry={() => void query.refetch()}/>
      : first && first.state !== "ok" && (!rows.length || first.state === "denied" || first.state === "error" || first.state === "not_collected") ? <ReportState state={first.state} details={first.state_details} detail={first.state === "empty" ? emptyDetail : undefined}/>
      : !rows.length ? <ReportState state="empty" detail={emptyDetail}/>
      : <>
        {first && first.state !== "ok" && first.state !== "empty" && !(problemEvidence && first.state === "partial" && first.coverage.evidence_missing_sources) ? <ReportState state={first.state} details={first.state_details} compact/> : null}
        {problemEvidence && total == null ? <p className="sli-ds-note" aria-live="polite">{t("security.problems.evidence.lower_bound", { count: lowerBound })}</p> : null}
        {missingSources ? <p className="sli-ds-note">{t("security.problems.evidence.partial", { count: missingSources })}</p> : null}
        <DataTable caption={detail.title} columns={columns} rows={rows} rowKey={rowKey} onRowClick={pick} selectedKey={chosen ? rowKey(chosen) : null}
          total={total ?? undefined} hasMore={Boolean(query.hasNextPage) && !query.isFetchNextPageError} loadingMore={query.isFetchingNextPage} onLoadMore={() => void query.fetchNextPage()}/>
        {query.isFetchNextPageError ? <ReportState state="error" compact onRetry={() => void query.fetchNextPage()}/> : null}
      </>}
    {RowComponent && chosen ? <div aria-label={t("reports.detail.selected_row_aria")}><RowComponent row={chosen} parent={row} params={new URLSearchParams(baseParams)}/></div> : RowComponent ? <p className="sli-ds-header__subtitle">{t("reports.detail.select_row_hint")}</p> : null}
    {!gpoReport && first?.limitations.length ? <ul className="sli-ds-state__text">{first.limitations.map((item) => <li key={item.code + item.text}>{item.text}</li>)}</ul> : null}
    {Actions ? <Actions row={row}/> : null}
  </section>;
}
