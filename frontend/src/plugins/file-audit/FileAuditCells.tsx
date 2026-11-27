import type { ReportColumnDto } from "../../api/report-v2-types";
import { useMutation } from "@tanstack/react-query";
import { api } from "../../api/client";
import { Button, type TableColumn } from "../../design-system";
import { formatDateTime } from "../../shared/date-time";
import { useTimeZone } from "../../shared/time-zone";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { columnValue, readPath } from "../../app/report-v2/state";
import { withDomain } from "../../app/domain-navigation";
import { t, type MessageKey } from "../../i18n";
import { fileMaskLabel, type FileMaskLabels } from "./permissionMasks";
import { fileAuditHref, fileAuditShare, type FileAuditRow, type FileAuditTab, type FileServerView } from "./report";

export const fileMaskLabels = (): FileMaskLabels => ({
  none: t("file-audit.permissions.none"), read: t("file-audit.permissions.read"),
  write: t("file-audit.permissions.write"), readWrite: t("file-audit.permissions.read_write"),
  readExecute: t("file-audit.permissions.read_execute"), modify: t("file-audit.permissions.modify"),
  full: t("file-audit.permissions.full"), custom: t("file-audit.permissions.custom"),
});

export function FileAuditInterval({ row }: { row: FileAuditRow }) {
  const { formatCell } = useDateFormatters();
  const { timeZone } = useTimeZone();
  const aggregate = row.aggregate as { first_seen_utc?: string; last_seen_utc?: string; count?: number } | undefined;
  if (!aggregate?.first_seen_utc) return <>{formatCell(row.observed_at, "datetime")}</>;
  const first = aggregate.first_seen_utc;
  const last = aggregate.last_seen_utc;
  const start = formatDateTime(first, timeZone, { seconds: true, withYear: false });
  const end = last && last !== first ? formatDateTime(last, timeZone, { seconds: true, withYear: false,
    timeOnly: formatDateTime(first, timeZone, { withTime: false }) === formatDateTime(last, timeZone, { withTime: false }) }) : null;
  return <span className="sli-file-audit__interval">
    <span>{start}{end ? "\u2013" + end : null}</span>{aggregate.count != null ? <small>×{aggregate.count}</small> : null}
  </span>;
}

const hostText = (value: unknown, limit = 4096) => typeof value === "string" ? value.slice(0, limit) : undefined;
const when = (key: string) => ({ key, kind: "datetime" as const });
const problemNumber = (row: FileAuditRow) => {
  const value = row.problem_id;
  return (typeof value === "number" && Number.isSafeInteger(value) || typeof value === "string") && /^[1-9]\d*$/.test(String(value))
    ? String(value) : null;
};

export function evidenceRecordNumbers(row: FileAuditRow) {
  if (!Array.isArray(row.evidence)) return [];
  const records = row.evidence.flatMap((item: unknown) => {
    if (!item || typeof item !== "object" || !("event_id" in item) || !Number.isSafeInteger(item.event_id)) return [];
    const record = "record_id" in item && (typeof item.record_id === "number" || typeof item.record_id === "string")
      ? String(item.record_id) : "";
    return [/^[1-9]\d{0,19}$/.test(record) ? String(item.event_id) + " · " + record : String(item.event_id)];
  });
  return records.length ? [{ label: t("file-audit.screen.security_event"), value: [...new Set(records)].join(", ") }] : [];
}

export function fileAuditOperation(row: FileAuditRow, column?: ReportColumnDto) {
  if (row.operation === "permissions") return t("file-audit.screen.permission_change");
  if (row.operation === "access_denied" || !column && row.outcome === "failure") return t("file-audit.screen.access_denied");
  const known = ["read", "write", "delete", "rename", "delete_right", "share_change", "audit_change", "access_check", "unknown"] as const;
  const operation = known.find(value => value === row.operation);
  return operation ? t("reports.v2.file-audit.actions.columns.operation.labels." + operation as "reports.v2.file-audit.actions.columns.operation.labels.read")
    : column ? columnValue(column, row) : undefined;
}

export function fileServerColumns(view: FileServerView, declared: ReportColumnDto[], rows: FileAuditRow[],
  params: URLSearchParams | null, canPermissions: boolean, open: (row: FileAuditRow) => void,
  hrefFor: (tab: FileAuditTab, row: FileAuditRow, extra?: Record<string, string | null>) => string,
  refresh: () => void): TableColumn<FileAuditRow>[] {
  const operation = declared.find(column => column.key === "operation");
  if (view === "actions") {
    const columns: TableColumn<FileAuditRow>[] = [
      { ...when("observed_at"), label: t("file-audit.screen.time"), render: row => <FileAuditInterval row={row}/> },
      { key: "operation", label: t("file-audit.operation"), value: row => fileAuditOperation(row, operation) },
      { key: "path", label: t("file-audit.screen.path"), wrap: true, width: "35%", render: row =>
        <button type="button" className="sli-ds-table__link" onClick={event => { event.stopPropagation(); open(row); }}>{hostText(row.path) ?? "—"}</button> },
      { key: "account", label: t("file-audit.screen.who"), value: row => hostText(row.subject_name, 256) || hostText(row.subject_sid, 256) },
      { key: "client_ip", label: t("file-audit.screen.from"), value: row => hostText(row.client_ip, 64) },
      { key: "source_name", label: t("file-audit.workspace.server"), value: row => hostText(row.source_name, 256) },
      { key: "problem", label: t("file-audit.screen.problem"), render: row => {
        const id = problemNumber(row);
        return id ? <a href={withDomain('/app/report/security.problems?id=' + id, window.location.search)}
          onClick={event => event.stopPropagation()}>{t("file-audit.screen.problem_number", { id })}</a> : null;
      } },
    ];
    return columns.filter(column => column.key !== "client_ip" || rows.some(row => hostText(row.client_ip, 64)));
  }
  if (view === "permissions") return [
    { key: "source_name", label: t("file-audit.workspace.server"), value: row => hostText(row.source_name, 256) },
    { key: "path", label: t("file-audit.screen.path"), wrap: true, width: "32%", render: row =>
      canPermissions && row.snapshot_id && fileAuditShare(row) ? <button type="button" className="sli-ds-table__link"
        onClick={event => { event.stopPropagation(); open(row); }}>{hostText(row.path) ?? "—"}</button> : hostText(row.path) ?? "—" },
    ...declared.filter(column => ["rule_code", "employee", "share_mask", "smb_mask", "ntfs_mask"].includes(column.key)).map(column => ({
      key: column.key, label: column.label, value: (row: FileAuditRow) =>
        ["share_mask", "smb_mask", "ntfs_mask"].includes(column.key)
          ? fileMaskLabel(readPath(row, column.path), fileMaskLabels()) ?? columnValue(column, row)
          : columnValue(column, row),
    })),
    { ...when("observed_at"), label: t("file-audit.workspace.snapshot") },
  ];
  const count = (row: FileAuditRow) => row.permission_changes != null ? String(row.permission_changes)
    : row.permission_change_count_min != null && row.permission_change_count_max != null
      ? String(row.permission_change_count_min) + '–' + String(row.permission_change_count_max) : t("file-audit.resources.notCollected");
  return [
    { key: "source_name", label: t("file-audit.workspace.server"), render: row => {
      const name = hostText(row.source_name, 256);
      return name && typeof row.source_instance_id === "string" && params
        ? <a onClick={event => event.stopPropagation()} href={withDomain(fileAuditHref("overview", params, undefined,
          { source_instance_id: row.source_instance_id, share: null, path: null }), window.location.search)}>{name}</a> : name ?? "—";
    } },
    { key: "resource", label: t("file-audit.workspace.resource_path"), width: "27%", wrap: true, render: row => {
      const name = hostText(row.share_name, 256) || hostText(row.path) || "—";
      return <span className="sli-file-audit__resource">
        {canPermissions && row.snapshot_id && fileAuditShare(row) ? <button type="button" className="sli-ds-table__link"
          onClick={event => { event.stopPropagation(); open(row); }}>{name}</button> : name}
        {row.share_name ? <small>{hostText(row.path)}</small> : null}
      </span>;
    } },
    { ...when("audit_received_at"), label: t("file-audit.screen.audit"), wrap: true, render: row =>
      <div className="sli-file-audit__resource">
        <span><FileAuditReceipt row={row}/></span>
        {row.audit_state === "enabled" || row.audit_state != null && row.audit_received_at
          ? <ResourceBatch receivedAt={row.audit_received_at}/> : null}
        {Number.isSafeInteger(row.check_revision) && fileAuditShare(row) ? <FileAuditCheck row={row} refresh={refresh}/> : null}
      </div> },
    { key: "permission_changes", label: t("file-audit.workspace.permission_changes"), kind: "number", render: row =>
      fileAuditShare(row) && Number(row.permission_change_groups) > 0
        ? <a href={hrefFor("permission-changes", row)} onClick={event => event.stopPropagation()}>{count(row)}</a> : count(row) },
    { ...when("observed_at"), label: t("file-audit.workspace.snapshot"), render: row => <ResourceSnapshot row={row}/> },
  ];
}

function ResourceBatch({ receivedAt }: { receivedAt: FileAuditRow["audit_received_at"] }) {
  const { formatCell } = useDateFormatters();
  return <small>{receivedAt ? t("file-audit.screen.last_batch", { time: formatCell(receivedAt, "datetime") })
    : t("file-audit.screen.no_batch")}</small>;
}

function ResourceSnapshot({ row }: { row: FileAuditRow }) {
  const { formatCell } = useDateFormatters();
  return <span>{row.snapshot_id && row.observed_at ? formatCell(row.observed_at, "datetime") : t("file-audit.resources.notCollected")}</span>;
}

const resourceAuditReasons: Record<string, MessageKey> = {
  sacl_missing: "file-audit.screen.sacl_missing",
  policy_missing: "file-audit.screen.audit_policy_missing",
  policy_blocked: "file-audit.resources.policyBlocked",
  managed_by_gpo: "file-audit.resources.policyBlocked",
  management_disabled: "file-audit.resources.managementOff",
  native_unavailable: "file-audit.screen.audit_unreadable",
  coverage_incomplete: "file-audit.screen.inventory_incomplete",
  share_read_unavailable: "file-audit.resources.shareUnavailable",
  share_path_mismatch: "file-audit.resources.shareUnavailable",
  directory_root_invalid: "file-audit.resources.shareUnavailable",
  directory_open_unavailable: "file-audit.resources.shareUnavailable",
  directory_reparse_point: "file-audit.resources.shareUnavailable",
  acl_read_unavailable: "file-audit.resources.entriesUnavailable",
  sacl_plan_failed: "file-audit.resources.entriesUnavailable",
  sacl_write_failed: "file-audit.resources.entriesUnavailable",
  sacl_readback_failed: "file-audit.resources.entriesUnavailable",
  restore_conflict: "file-audit.resources.restoreConflict",
  restore_incomplete: "file-audit.resources.restoreIncomplete",
  restore_scan_incomplete: "file-audit.resources.restoreIncomplete",
  inheritance_untracked: "file-audit.resources.restoreIncomplete",
};

function FileAuditReceipt({ row }: { row: FileAuditRow }) {
  const { formatCell } = useDateFormatters();
  const receipt = (row.check_receipt ?? row.audit_receipt) as { action?: string; state?: string; reason_code?: string; observed_at?: string;
    check_agent_requirement?: { agent_version: string; minimum_version: string } } | undefined;
  if (row.audit_state === "applying" || row.audit_state === "restoring" || row.audit_state === "enabled")
    return <>{t(`file-audit.resources.${row.audit_state}`)}{row.audit_state === "enabled" && row.audit_checked_at
      ? ` · ${formatCell(row.audit_checked_at, "datetime")}` : null}</>;
  if (row.check_pending === true) return <>{t("file-audit.screen.check_pending")}</>;
  if (row.audit_state === "error") {
    const code = typeof row.audit_reason === "string" ? row.audit_reason.split(":")[0] : "";
    const reason = Object.hasOwn(resourceAuditReasons, code) ? resourceAuditReasons[code] : "file-audit.screen.audit_failed";
    return <>{t("file-audit.resources.error", { reason: t(reason) })}</>;
  }
  if (row.audit_state === "disabled" && !row.check_receipt && receipt?.action !== "check")
    return <>{t("file-audit.resources.disabled")}</>;
  const checkResult = row.check_receipt != null || receipt?.action === "check";
  const failure = receipt?.state === "failed" || receipt?.state === "blocked" || receipt?.state === "partial";
  if (receipt?.observed_at && (checkResult || failure &&
      Date.parse(receipt.observed_at) >= (Date.parse(String(row.audit_received_at)) || 0))) {
    const reason = receipt.reason_code === "native_unavailable" ? "file-audit.screen.audit_unreadable"
      : receipt.reason_code === "sacl_missing" ? "file-audit.screen.sacl_missing"
      : receipt.reason_code === "policy_missing" ? "file-audit.screen.audit_policy_missing"
      : receipt.reason_code === "coverage_incomplete" ? "file-audit.screen.inventory_incomplete"
      : receipt.state === "verified" ? "file-audit.screen.check_verified"
      : receipt.state === "partial" ? "file-audit.screen.check_partial" : "file-audit.screen.audit_failed";
    const requirement = receipt.check_agent_requirement;
    return <>{requirement ? t("file-audit.screen.update_agent", { version: requirement.agent_version, minimum: requirement.minimum_version })
      : t(reason)} · {formatCell(receipt.observed_at, "datetime")}</>;
  }
  return <>{row.audit_received_at ? formatCell(row.audit_received_at, "datetime") : t("file-audit.screen.no_batch")}</>;
}

function FileAuditCheck({ row, refresh }: { row: FileAuditRow; refresh: () => void }) {
  const check = useMutation({
    mutationFn: () => api.agentAction("file-audit", {
      agent_id: row.agent_id, source_instance_id: row.source_instance_id,
      collection_scope_id: row.collection_scope_id, expected_revision: row.check_revision,
    }),
    onSettled: refresh,
  });
  return <div>
    <Button disabled={check.isPending || row.check_pending === true} onClick={() => check.mutate()}>
      {t("file-audit.screen.check")}
    </Button>
    {check.isError ? <div role="alert">{t("file-audit.screen.check_request_failed")}</div> : null}
  </div>;
}
