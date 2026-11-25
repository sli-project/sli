import type { ReactNode } from "react";
import type { ReportColumnDto } from "../../api/report-v2-types";
import { SeverityBadge, type TableColumn } from "../../design-system";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { columnValue, readPath } from "../../app/report-v2/state";
import { tableColumns } from "../../app/report-v2/DetailSection";
import { withDomain } from "../../app/domain-navigation";
import { t } from "../../i18n";
import { fileMaskLabel, type FileMaskLabels } from "./permissionMasks";
import { fileAuditHref, fileAuditShare, type FileAuditRow, type FileAuditTab } from "./report";

export const fileMaskLabels = (): FileMaskLabels => ({
  none: t("file-audit.permissions.none"), read: t("file-audit.permissions.read"),
  write: t("file-audit.permissions.write"), readWrite: t("file-audit.permissions.read_write"),
  readExecute: t("file-audit.permissions.read_execute"), modify: t("file-audit.permissions.modify"),
  full: t("file-audit.permissions.full"), custom: t("file-audit.permissions.custom"),
});

export function FileAuditStatus({ state, children }: { state: unknown; children: ReactNode }) {
  const tone = ["complete", "verified", "imported"].includes(String(state)) ? "success"
    : ["failed", "blocked"].includes(String(state)) ? "danger"
    : ["partial", "pending", "pending_import"].includes(String(state)) ? "warning" : "neutral";
  return <span className="sli-file-audit__status" title={typeof children === "string" ? children : undefined}>
    <span className="sli-file-audit__dot" data-tone={tone} aria-hidden="true"/>{children}
  </span>;
}

export function FileAuditInterval({ row }: { row: FileAuditRow }) {
  const { formatCell } = useDateFormatters();
  const aggregate = row.aggregate as { first_seen_utc?: string; last_seen_utc?: string } | undefined;
  if (!aggregate?.first_seen_utc) return <>{formatCell(row.observed_at, "datetime")}</>;
  return <span className="sli-file-audit__interval">
    {formatCell(aggregate.first_seen_utc, "datetime")}
    {aggregate.last_seen_utc && aggregate.last_seen_utc !== aggregate.first_seen_utc
      ? <small>— {formatCell(aggregate.last_seen_utc, "datetime")}</small> : null}
  </span>;
}

export function FileAuditCount({ row }: { row: FileAuditRow }) {
  const aggregate = row.aggregate as { count?: number; boundary?: string } | undefined;
  return <>{aggregate?.count == null ? "—" : aggregate.boundary === "overlap"
    ? t("file-audit.workspace.group_count", { count: aggregate.count }) : aggregate.count}</>;
}

export function fileAuditColumns(columns: ReportColumnDto[], timeZone: string, tab: FileAuditTab,
  rows: FileAuditRow[], params: URLSearchParams | null, open: (row: FileAuditRow) => void,
  hrefFor: (tab: FileAuditTab, row: FileAuditRow, extra?: Record<string, string | null>) => string) {
  const declared = tableColumns(columns, timeZone).filter(column =>
    !["client_ip", "process", "process_name"].includes(column.key) || rows.some(row => row[column.key] != null));
  const result = declared.map((column): TableColumn<FileAuditRow> => {
    const definition = columns.find(item => item.key === column.key)!;
    if (["share_mask", "smb_mask", "ntfs_mask"].includes(column.key)) return { ...column,
      value: row => fileMaskLabel(readPath(row, definition.path), fileMaskLabels()) ?? columnValue(definition, row) };
    if (["completeness", "audit_state", "delivery_state"].includes(column.key)) return { ...column,
      render: row => <FileAuditStatus state={readPath(row, definition.path)}>{String(columnValue(definition, row) ?? "—")}</FileAuditStatus> };
    if (column.key === "observed_at" && rows.some(row => row.aggregate)) return { ...column,
      label: t("file-audit.workspace.interval"), render: row => <FileAuditInterval row={row}/> };
    if (column.key === "path") return { ...column, wrap: true, minWidth: "14rem", render: row =>
      <button type="button" className="sli-ds-table__link" onClick={event => { event.stopPropagation(); open(row); }}>{String(row.path ?? "—")}</button> };
    if (column.key === "unread_objects") return { ...column, label: t("file-audit.workspace.scan_gaps") };
    return { ...column, sortable: false };
  });
  if (["actions", "permission-changes"].includes(tab) && rows.some(row => row.aggregate) && !result.some(column => column.key === "count")) {
    result.push({ key: "count", label: t("file-audit.workspace.count"), kind: "number", render: row => <FileAuditCount row={row}/> });
  }
  if (tab !== "overview" || !columns.some(column => column.key === "permission_changes")) return result;
  const dateColumn = (key: string) => result.find(column => column.key === key);
  const count = (row: FileAuditRow) => row.permission_changes != null ? String(row.permission_changes)
    : row.permission_change_count_min != null && row.permission_change_count_max != null
      ? `${row.permission_change_count_min}–${row.permission_change_count_max}` : "—";
  const overviewColumns: TableColumn<FileAuditRow>[] = [
    { key: "source_name", label: t("file-audit.workspace.server"), width: "12%", render: row =>
      typeof row.source_instance_id === "string" && params
        ? <a onClick={event => event.stopPropagation()} href={withDomain(fileAuditHref("overview", params, undefined,
          { source_instance_id: row.source_instance_id, share: null, path: null }), window.location.search)}>{String(row.source_name ?? row.source_instance_id)}</a>
        : String(row.source_name ?? "—") },
    { key: "resource", label: t("file-audit.workspace.resource_path"), width: "28%", wrap: true, render: row => <span className="sli-file-audit__resource">
      <button type="button" className="sli-ds-table__link" onClick={event => { event.stopPropagation(); open(row); }}>{String(row.share_name ?? row.share_label ?? row.path ?? "—")}</button>
      <small>{String(row.path ?? "")}</small>
    </span> },
    { key: "fact", label: t("file-audit.workspace.observed_fact"), wrap: true, render: row =>
      typeof row.fact === "string" ? <span>{row.severity ? <SeverityBadge severity={row.severity}/> : null}{row.fact}</span>
      : Number(row.unread_objects) > 0 ? <span>{t("file-audit.workspace.scan_gaps")}: {String(row.unread_objects)}</span> : "—" },
    { key: "permission_changes", label: t("file-audit.workspace.permission_changes"), kind: "number", render: row =>
      fileAuditShare(row) ? <a href={hrefFor("permission-changes", row)} onClick={event => event.stopPropagation()}
        title={Number(row.permission_change_boundary_groups) > 0 ? t("file-audit.workspace.boundary") : undefined}>{count(row)}</a> : count(row) },
    { ...dateColumn("last_permission_change"), key: "last_permission_change", label: t("file-audit.workspace.last_change"), kind: "datetime" },
    { ...dateColumn("observed_at"), key: "observed_at", label: t("file-audit.workspace.snapshot"), kind: "datetime" },
  ];
  return overviewColumns.filter(column => column.key !== "fact" || rows.some(row => typeof row.fact === "string" && row.fact.length > 0 || Number(row.unread_objects) > 0));
}
