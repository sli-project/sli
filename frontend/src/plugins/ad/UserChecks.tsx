import { useTimeZone } from "../../shared/time-zone";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { memo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { ReportColumnDto, ReportResultDto } from "../../api/report-v2-types";
import { DataTable, FactList, formatCell, type TableColumn } from "../../design-system";
import { ReviewList, type ReviewItem } from "../../design-system/ReviewList";
import { t } from "../../i18n";
import { tableColumns } from "../../app/report-v2/DetailSection";
import { columnValue } from "../../app/report-v2/state";
import { LastWorkplace } from "./ReportAdditions";

type Row = Record<string, unknown>;
const text = (value: unknown) => typeof value === "string" && value.trim() ? value : null;
const object = (value: unknown): Row => value && typeof value === "object" ? value as Row : {};
const objects = (value: unknown): Row[] => Array.isArray(value) ? value.filter((item): item is Row => Boolean(item) && typeof item === "object") : [];
const count = (value: unknown) => typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
const missing = () => t("table.noValue");
function useDate() {
  const { formatDateTime } = useDateFormatters();
  return (value: unknown) => formatDateTime(text(value));
}

export function userSummary(result?: ReportResultDto) {
  if (!result) return undefined;
  return t("reports.ad.users.summary", { count: count(result.coverage.population) ?? count(result.coverage.users) ?? missing(),
    affected: count(result.coverage.affected_objects) ?? missing() });
}

export function userTableColumns(columns: ReportColumnDto[], onSelect: (row: Row) => void, privileged: boolean, timeZone?: string): TableColumn<Row>[] {
  return tableColumns(columns, timeZone).map((column) => ({ ...column,
    hiddenByDefault: !["name", "state", "ou", "last_workplace", "password_last_set", ...(privileged ? ["privilege_basis", "nested_privilege_groups"] : [])].includes(column.key),
    mobile: ["name", "state", ...(privileged ? ["privilege_basis"] : [])].includes(column.key),
    render: column.key === "name" ? (row) => <>
      <button type="button" className="sli-ds-button" data-variant="ghost" onClick={(event) => { event.stopPropagation(); onSelect(row); }}>{text(row.sam) ?? text(row.display_name) ?? missing()}</button>
      {text(row.display_name) && row.display_name !== row.sam ? <div className="sli-ds-muted">{String(row.display_name)}</div> : null}
    </> : column.render ?? ((row) => columnValue(columns.find((item) => item.key === column.key)!, row) == null ? missing() : formatCell(columnValue(columns.find((item) => item.key === column.key)!, row), column.kind, timeZone)),
  }));
}


function CheckObjects({ check, baseParams, onSelect }: { check: Row; baseParams: string; onSelect: (row: Row) => void }) {
  const date = useDate();
  const [all, setAll] = useState(false);
  const [cursors, setCursors] = useState<Array<string | null>>([null]);
  const cursor = cursors[cursors.length - 1];
  const query = useQuery({ queryKey: ["ad-user-check", baseParams, check.key, cursor], queryFn: () => {
    const params = new URLSearchParams(baseParams);
    params.set("tab", "checks"); params.set("check", String(check.key)); params.set("limit", "50");
    if (cursor) params.set("cursor", cursor); else params.delete("cursor");
    return api.reportV2Data("ad.users.v2", params);
  }, enabled: all, retry: false, staleTime: 60_000, refetchOnWindowFocus: false });
  const preview = objects(check.objects);
  const rows = all ? query.data?.items ?? [] : preview;
  const select = (row: Row) => onSelect({ ...row, id: row.entity_id, display_name: row.name ?? row.display_name,
    sam: row.domain_name && row.name ? `${row.domain_name}\\${row.name}` : row.sam,
    review_details: [{ label: check.title, observed: row.observed_at_utc, qualification: check.why, next: check.action }] });
  const columns: TableColumn<Row>[] = [
    { key: "name", label: t("reports.ad.users.account"), render: (row) => <><button type="button" className="sli-ds-button" data-variant="ghost" onClick={() => select(row)}>{text(row.name) ?? text(row.sam) ?? missing()}</button><div className="sli-ds-muted">{text(row.domain_name) ?? missing()}</div></> },
    { key: "observed_at_utc", label: t("reports.ad.users.observed"), render: (row) => date(row.observed_at_utc) },
    { key: "activity_at", label: t("reports.ad.users.activity"), render: (row) => date(row.activity_at), mobile: false },
    { key: "ou", label: "OU", render: (row) => text(row.ou) ?? missing(), mobile: false },
  ];
  return <>
    {all && query.isLoading ? <p role="status">{t("table.loadingMore")}</p> : null}
    {all && (query.error || query.data?.state === "error") ? <p role="alert">
      {t("reports.ad.users.objects_unavailable", { check: text(check.title) ?? missing() })}{" "}
      <button type="button" className="sli-ds-button" onClick={() => void query.refetch()}>{t("state.retry")}</button>
    </p> : null}
    {rows.length ? <DataTable caption={String(check.title)} columns={columns} rows={rows} rowKey={(row) => `${row.domain_id}:${row.entity_id ?? row.name}`}
      stickyHeader={false} showFooter={all} total={all ? query.data?.filtered_count : undefined}
      pagination={all ? { start: (cursors.length - 1) * 50 + 1, busy: query.isFetching,
        onPrevious: cursors.length > 1 ? () => setCursors((current) => current.slice(0, -1)) : undefined,
        onNext: query.data?.has_more && query.data.next_cursor ? () => setCursors((current) => [...current, query.data!.next_cursor]) : undefined } : undefined}/> : null}
    {!all ? <button type="button" className="sli-ds-button" onClick={() => setAll(true)}>{t("reports.ad.users.open_all")}</button> : null}
  </>;
}

export const UserChecks = memo(function UserChecks({ result, baseParams, onSelect }: { result?: ReportResultDto; baseParams: string; onSelect: (row: Row) => void }) {
  const date = useDate();
  const checks = (result?.collections?.checks ?? result?.items ?? []).filter((row) => row.section !== "not_evaluated");
  const item = (check: Row): ReviewItem => ({
    key: String(check.key), title: text(check.title) ?? missing(), severity: text(check.severity_text) ?? missing(),
    tone: check.severity === "high" ? "danger" : check.severity === "medium" ? "warning" : "neutral",
    status: check.status === "no_comparison" ? t("reports.ad.checks.status.no_comparison")
      : check.status === "not_evaluated" || check.status_text === t("reports.ad.checks.status.not_evaluated")
      ? missing() : text(check.status_text) ?? missing(),
    total: count(check.total), newCount: count(check.new_count),
    detail: <>
      <p><strong>{t("reports.ad.checks.column.why")}: </strong>{text(check.why) ?? missing()}</p>
      <p><strong>{t("reports.ad.checks.column.action")}: </strong>{text(check.action) ?? missing()}</p>
      <p className="sli-ds-muted">{t("reports.ad.users.observed")}: {date(check.last_seen_utc)} · {t("reports.ad.users.actor")}: {text(object(check.change).actor) ?? missing()}</p>
      <CheckObjects check={check} baseParams={baseParams} onSelect={onSelect}/>
    </>,
  });
  return <ReviewList compact summaryOnly items={checks.map(item).filter((check) => check.status !== missing() || check.total !== null || check.newCount !== null)}/>;
});

export const UserChanges = memo(function UserChanges({ columns, rows, title, onSelect }: { columns: ReportColumnDto[]; rows: Row[]; title: string; onSelect: (row: Row) => void }) {
  const { timeZone } = useTimeZone();
  const { formatCell } = useDateFormatters();
  const mapped = tableColumns(columns, timeZone).map((column) => ({ ...column, mobile: ["name", "change"].includes(column.key),
    render: column.key === "name" ? (row: Row) => <button type="button" className="sli-ds-button" data-variant="ghost" onClick={() => onSelect(row)}>{text(row.sam) ?? text(row.display_name) ?? missing()}</button>
      : column.render ?? ((row: Row) => {
        const value = column.value?.(row);
        return value === null || value === undefined || value === "" ? missing() : formatCell(value, column.kind);
      }),
  }));
  return <DataTable caption={title} columns={mapped} rows={rows} rowKey={(row) => JSON.stringify(row)} onRowClick={onSelect}/>;
});

export function UserReasons({ row }: { row: Row }) {
  const date = useDate();
  const reasons = objects(row.review_details);
  const paths = objects(row.membership_paths);
  const change = object(row.change);
  return <>
    <section><h3 className="sli-ds-section-title">{t("reports.ad.users.workplace")}</h3><LastWorkplace row={row}/></section>
    <section><h3 className="sli-ds-section-title">{t("reports.ad.users.reasons")}</h3>
      {reasons.length ? reasons.map((reason, index) => <section key={index}>
        <h4>{text(reason.label) ?? missing()}</h4><FactList facts={[
          { label: t("reports.ad.users.observed"), value: text(reason.observed) ?? missing() },
          { label: t("reports.ad.checks.column.why"), value: text(reason.qualification) ?? missing() },
          { label: t("reports.ad.checks.column.action"), value: text(reason.next) ?? missing() },
        ]}/></section>) : <p>{t("reports.ad.users.no_recorded_reasons")}</p>}
    </section>
    <section><h3 className="sli-ds-section-title">{t("reports.ad.users.groups")}</h3>
      {paths.length ? <ul>{paths.map((path, index) => <li key={index}>{objects(path.nodes).map((node) => text(node.name) ?? missing()).join(" → ")}</li>)}</ul>
        : <p>{Array.isArray(row.direct_groups) && row.direct_groups.length ? row.direct_groups.join(", ") : missing()}</p>}
    </section>
    <section><h3 className="sli-ds-section-title">{t("reports.ad.users.history")}</h3>
      <p>{text(change.at_utc) ? <>{date(change.at_utc)} · {text(change.actor) ?? missing()}</> : missing()}</p>
    </section>
  </>;
}
