import { useTimeZone } from "../../shared/time-zone";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { memo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { ReportColumnDto, ReportResultDto } from "../../api/report-v2-types";
import { DataTable, SeverityBadge, formatCell, type TableColumn } from "../../design-system";
import { isSeverity } from "../../design-system/SeverityBadge";
import { ReviewList, type ReviewItem } from "../../design-system/ReviewList";
import { t, type MessageKey } from "../../i18n";
import { tableColumns } from "../../app/report-v2/DetailSection";

type Row = Record<string, unknown>;
export const userText = (value: unknown) => typeof value === "string" && value.trim() ? value : null;
export const userObject = (value: unknown): Row => value && typeof value === "object" ? value as Row : {};
export const userObjects = (value: unknown): Row[] => Array.isArray(value) ? value.filter((item): item is Row => Boolean(item) && typeof item === "object") : [];
const text = userText;
const object = userObject;
const objects = userObjects;
const count = (value: unknown) => typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
const missing = () => t("table.noValue");
const deviations: Record<string, MessageKey> = {
  locked_out: "reports.ad.users.deviation.locked_out",
  account_expired: "reports.ad.users.deviation.account_expired",
  password_expired: "reports.ad.users.deviation.password_expired",
  sensitive_uac_flag: "reports.ad.users.deviation.sensitive_setting",
  watch_group_membership: "reports.ad.users.deviation.monitored_group",
  password_not_required: "reports.ad.users.deviation.password_not_required",
  kerberos_no_preauth: "reports.ad.users.deviation.kerberos_no_preauth",
  spn_privileged: "reports.ad.users.deviation.spn_privileged",
  spn_old_password: "reports.ad.users.deviation.spn_old_password",
  privileged_password_never_expires: "reports.ad.users.list.password_no_expiry",
  temporary_membership: "reports.ad.users.deviation.temporary_membership",
};

function deviationText(row: Row) {
  const reasons = objects(row.reasons).map((reason) => {
    const key = String(reason.key);
    const days = count(object(reason.policy).threshold_days);
    if (days !== null && key === "password_age") return t("reports.ad.users.deviation.password_age", { days });
    if (days !== null && key === "inactive_threshold") return t("reports.ad.users.deviation.inactive", { days });
    return Object.hasOwn(deviations, key) ? t(deviations[key]) : text(reason.label);
  }).filter(Boolean);
  return (reasons.length ? reasons.join(" · ") : text(row.reason_text))
    ?? (row.password_never_expires === true ? t("reports.ad.users.list.password_no_expiry") : null);
}
function useDate() {
  const { formatDateTime } = useDateFormatters();
  return (value: unknown) => formatDateTime(text(value));
}

export function userTableColumns(columns: ReportColumnDto[], onSelect: (row: Row, tab?: string) => void, timeZone?: string): TableColumn<Row>[] {
  const order = ["name", "privilege_basis", "department", "ou", "activity", "last_workplace", "password_last_set", "groups", "reason"];
  const labels: Record<string, string> = {
    name: t("reports.ad.users.list.name"), privilege_basis: t("reports.ad.users.list.privileges"),
    last_workplace: t("reports.ad.users.list.computer"), groups: t("reports.ad.users.list.direct_groups"),
    reason: t("reports.ad.users.list.deviation"),
  };
  const mapped = tableColumns(columns.filter((column) => order.includes(column.key)), timeZone);
  return order.flatMap((key) => {
    const column = mapped.find((item) => item.key === key);
    if (!column) return [];
    return [{ ...column, label: labels[key] ?? column.label, hiddenByDefault: key === "name" ? undefined : false,
    render: (row: Row) => {
      if (key === "last_workplace") return text(object(row.last_workplace).computer) ?? missing();
      if (key === "reason") {
        const reason = deviationText(row);
        return reason ? <>{isSeverity(row.severity) ? <><SeverityBadge severity={row.severity}/> · </> : null}{reason}</> : missing();
      }
      if (key === "privilege_basis") {
        const groups = [row.privilege_basis, row.nested_privilege_groups].flatMap((group) => Array.isArray(group) ? group.filter((value) => typeof value === "string") : []);
        return groups.length ? <button type="button" className="sli-ds-link-button" onClick={(event) => {
          event.stopPropagation(); onSelect(row, "rights");
        }}>{[...new Set(groups)].join(", ")}</button> : missing();
      }
      if (key !== "name") return formatCell(column.value?.(row), key === "password_last_set" ? "date" : column.kind, timeZone);
      const name = text(row.account_display_name) ?? text(row.display_name);
      const account = text(row.sam) ?? name ?? missing();
      const displayName = name === account ? null : name;
      return <><span aria-hidden="true">{row.enabled === true ? "● " : row.enabled === false ? "⊘ " : ""}</span>
        {typeof row.enabled === "boolean" ? <span className="sli-ds-sr-only">{t(row.enabled ? "reports.ad.users.card.enabled" : "reports.ad.users.card.disabled")} </span> : null}
        <button type="button" className="sli-ds-link-button" onClick={(event) => { event.stopPropagation(); onSelect(row); }}>{account}</button>
        {displayName ? <> / {displayName}</> : null}</>;
    }}];
  });
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
    {all && query.error ? <div role="alert">{t("reports.ad.users.objects_unavailable")} <button type="button" className="sli-ds-button" onClick={() => void query.refetch()}>{t("state.retry")}</button></div> : null}
    {rows.length ? <DataTable caption={String(check.title)} columns={columns} rows={rows} rowKey={(row) => `${row.domain_id}:${row.entity_id ?? row.name}`}
      stickyHeader={false} showFooter={all} total={all ? query.data?.filtered_count : undefined}
      pagination={all ? { start: (cursors.length - 1) * 50 + 1, busy: query.isFetching,
        onPrevious: cursors.length > 1 ? () => setCursors((current) => current.slice(0, -1)) : undefined,
        onNext: query.data?.has_more && query.data.next_cursor ? () => setCursors((current) => [...current, query.data!.next_cursor]) : undefined } : undefined}/> : null}
    {!all ? <p><span>{t("reports.ad.users.preview", { count: preview.length, total: count(check.total) ?? missing() })}</span>{" · "}
      <button type="button" className="sli-ds-button" onClick={() => setAll(true)}>{t("reports.ad.users.open_all")}</button></p> : null}
  </>;
}

export const UserChecks = memo(function UserChecks({ result, baseParams, onSelect }: { result?: ReportResultDto; baseParams: string; onSelect: (row: Row) => void }) {
  const date = useDate();
  const checks = (result?.collections?.checks ?? result?.items ?? []).filter((row) => row.section !== "not_evaluated");
  const item = (check: Row): ReviewItem => ({
    key: String(check.key), title: text(check.title) ?? missing(), severity: check.severity,
    status: check.status === "no_comparison" ? t("reports.ad.checks.status.no_comparison")
      : check.status === "not_evaluated" || check.status_text === t("reports.ad.checks.status.not_evaluated")
      ? missing() : text(check.status_text) ?? missing(),
    total: count(check.total), newCount: count(check.new_count),
    detail: <>
      <p><strong>{t("reports.ad.checks.column.why")}: </strong>{text(check.why) ?? missing()}</p>
      <p><strong>{t("reports.ad.checks.column.action")}: </strong>{text(check.action) ?? missing()}</p>
      <details><summary>{t("reports.ad.checks.column.remediation")}</summary><p>{text(check.remediation) ?? missing()}</p></details>
      <p className="sli-ds-muted">{t("reports.ad.users.observed")}: {date(check.last_seen_utc)} · {t("reports.ad.users.actor")}: {text(object(check.change).actor) ?? missing()}</p>
      <CheckObjects check={check} baseParams={baseParams} onSelect={onSelect}/>
    </>,
  });
  return <ReviewList compact summaryOnly items={checks.map(item).filter((check) => check.status !== missing() || check.total !== null || check.newCount !== null)}/>;
});

export const UserChanges = memo(function UserChanges({ columns, rows, title, onSelect, paging }: { columns: ReportColumnDto[]; rows: Row[]; title: string; onSelect: (row: Row) => void; paging?: Pick<React.ComponentProps<typeof DataTable<Row>>, "pagination" | "pageSize" | "density" | "total"> }) {
  const { timeZone } = useTimeZone();
  const { formatCell } = useDateFormatters();
  const mapped = tableColumns(columns.filter((column) => !["field", "group", "note", "quality", "source_id", "activity_type", "delay_minutes", "logon_type", "evidence"].includes(column.key)
    && (column.key !== "actor" || rows.some((row) => text(row.actor)))), timeZone).map((column) => ({ ...column,
    render: column.key === "name" ? (row: Row) => <button type="button" className="sli-ds-link-button" onClick={(event) => { event.stopPropagation(); onSelect(row); }}>{text(row.sam) ?? text(row.display_name) ?? missing()}</button>
      : column.render ?? ((row: Row) => {
        const value = column.value?.(row);
        return value === null || value === undefined || value === "" ? missing() : formatCell(value, column.kind);
      }),
  }));
  return rows.length ? <DataTable caption={title} columns={mapped} rows={rows} rowKey={(row) => JSON.stringify(row)} onRowClick={onSelect} wrap {...paging}/>
    : <p>{missing()}</p>;
});
