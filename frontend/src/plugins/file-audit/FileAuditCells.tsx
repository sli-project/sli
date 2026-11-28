import type { ReportColumnDto } from "../../api/report-v2-types";
import { useMutation } from "@tanstack/react-query";
import { api } from "../../api/client";
import { Button, SeverityBadge, type TableColumn } from "../../design-system";
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
  if (row.operation === "access_denied" || row.outcome === "failure" && (!column || row.operation === "access_check"))
    return t("file-audit.screen.access_denied");
  const known = ["read", "write", "delete", "rename", "delete_right", "share_change", "audit_change", "access_check", "unknown"] as const;
  const operation = known.find(value => value === row.operation);
  return operation ? t("reports.v2.file-audit.actions.columns.operation.labels." + operation as "reports.v2.file-audit.actions.columns.operation.labels.read")
    : column ? columnValue(column, row) : undefined;
}

export function fileServerColumns(view: FileServerView, declared: ReportColumnDto[], rows: FileAuditRow[],
  params: URLSearchParams | null, canPermissions: boolean, open: (row: FileAuditRow) => void,
  hrefFor: (tab: FileAuditTab, row: FileAuditRow, extra?: Record<string, string | null>) => string,
  refresh: () => void, allowed: ReadonlySet<string>): TableColumn<FileAuditRow>[] {
  const operation = declared.find(column => column.key === "operation");
  if (view === "actions") {
    const columns: TableColumn<FileAuditRow>[] = [
      { ...when("observed_at"), label: t("file-audit.screen.time"), render: row => <FileAuditInterval row={row}/> },
      { key: "operation", label: t("file-audit.operation"), value: row => fileAuditOperation(row, operation) },
      { key: "path", label: t("file-audit.screen.path"), wrap: true, width: "35%", render: row => {
        const path = hostText(row.path);
        const previous = row.operation === "rename" ? hostText(row.old_path) : undefined;
        return <button type="button" className="sli-ds-table__link" onClick={event => { event.stopPropagation(); open(row); }}>
          {path && previous ? previous + " → " + path : path ?? "—"}
        </button>;
      } },
      { key: "account", label: t("file-audit.screen.who"), width: "20%", value: row => hostText(row.subject_name, 256) || hostText(row.subject_sid, 256) },
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
  if (view === "audit-state") return [
    { key: "source_name", label: t("file-audit.workspace.server"), value: row => hostText(row.source_name, 256) },
    { key: "resource", label: t("file-audit.workspace.resource_path"), width: "18%", wrap: true, render: resourceName },
    { key: "audit_state", label: t("file-audit.screen.audit"), value: auditStatus },
    { key: "audit_condition", label: t("file-audit.audit.condition"), width: "21%", value: row => fileAuditShare(row)
      ? t("file-audit.audit.windows_condition") : t("file-audit.audit.not_collected") },
    { key: "audit_observed", label: t("file-audit.audit.observed"), width: "22%", wrap: true, render: row =>
      <div className="sli-file-audit__resource">
        <span><FileAuditReceipt row={row}/></span>
        {row.audit_state === "enabled" ? <ResourceBatch receivedAt={row.audit_received_at}/> : null}
      </div> },
    { ...when("audit_checked_at"), label: t("file-audit.audit.checked"),
      value: row => readPath(row, "check_receipt.observed_at") ?? row.audit_checked_at ?? readPath(row, "audit_receipt.observed_at") },
    { key: "check", label: t("file-audit.screen.check"), render: row =>
      Number.isSafeInteger(row.check_revision) && fileAuditShare(row) ? <FileAuditCheck row={row} refresh={refresh}/>
        : Number.isSafeInteger(row.audit_revision) ? <Button disabled>{t("file-audit.screen.check")}</Button> : null },
  ];
  if (view !== "overview") return filteredColumns(view, declared, open);
  const count = (row: FileAuditRow) => row.permission_changes != null ? String(row.permission_changes)
    : row.permission_change_count_min != null && row.permission_change_count_max != null
      ? String(row.permission_change_count_min) + '–' + String(row.permission_change_count_max) : "—";
  return [
    { key: "source_name", label: t("file-audit.workspace.server"), render: row => {
      const name = hostText(row.source_name, 256);
      return name && typeof row.source_instance_id === "string" && params
        ? <a onClick={event => event.stopPropagation()} href={withDomain(fileAuditHref("overview", params, undefined,
          { source_instance_id: row.source_instance_id, share: null, path: null }), window.location.search)}>{name}</a> : name ?? "—";
    } },
    { key: "resource", label: t("file-audit.workspace.resource_path"), width: "25%", wrap: true, render: row =>
      resourceName(row, canPermissions && row.snapshot_id && fileAuditShare(row) ? () => open(row) : undefined) },
    { key: "top_fact", label: t("file-audit.overview.fact"), width: "27%", wrap: true, render: row =>
      <OverviewFact row={row} hrefFor={hrefFor} allowed={allowed}/> },
    { key: "permission_changes", label: t("file-audit.workspace.permission_changes"), kind: "number", render: row =>
      allowed.has("file-audit.permission-changes") && fileAuditShare(row) && Number(row.permission_change_groups) > 0
        ? <a href={hrefFor("permission-changes", row)} onClick={event => event.stopPropagation()}>{count(row)}</a> : <span>{count(row)}</span> },
    { ...when("latest_change_at"), label: t("file-audit.overview.latest_change"), render: row =>
      <ResourceDate value={row.latest_change_at}
        href={allowed.has("file-audit.permission-changes") && fileAuditShare(row) && typeof row.latest_change_id === "string"
          && typeof row.latest_change_path === "string" ? hrefFor("permission-changes", row, {
            detail_row: row.latest_change_id, path: row.latest_change_path, include_nested: "false",
          }) : undefined}/> },
    { ...when("observed_at"), label: t("file-audit.overview.snapshot"), render: row =>
      <ResourceDate value={row.snapshot_id ? row.observed_at : undefined}
        href={canPermissions && row.snapshot_id && fileAuditShare(row) ? hrefFor("permissions", row) : undefined}/> },
  ];
}

function resourceName(row: FileAuditRow, open?: () => void) {
  const name = hostText(row.share_name, 256) || hostText(row.path) || "—";
  const server = hostText(row.source_name, 256), share = hostText(row.share_name, 256);
  return <span className="sli-file-audit__resource" title={server && share ? `\\\\${server}\\${share}` : undefined}>
    {open ? <button type="button" className="sli-ds-table__link" onClick={open}>{name}</button> : name}
    {share ? <small>{hostText(row.path)}</small> : null}
  </span>;
}

const massLabels = {
  "file-audit.mass-read": "file-audit.overview.mass_read",
  "file-audit.mass-write": "file-audit.overview.mass_write",
  "file-audit.mass-delete": "file-audit.overview.mass_delete",
} as const;

const aclLabels = {
  "file-audit.broad-write": "file-audit.overview.broad_write",
  "file-audit.direct-user-rights": "file-audit.overview.direct_access",
  "file-audit.disabled-account-rights": "file-audit.overview.disabled_access",
  "file-audit.acl-review": "file-audit.overview.acl_review",
} as const;

function OverviewFact({ row, hrefFor, allowed }: {
  row: FileAuditRow;
  hrefFor: (tab: FileAuditTab, row: FileAuditRow, extra?: Record<string, string | null>) => string;
  allowed: ReadonlySet<string>;
}) {
  const fact = row.top_fact as { kind?: string; severity?: string; rule?: string; id?: string; paths?: number;
    subject?: string; layer?: string; path?: string; snapshot?: string } | undefined;
  if (!fact) return <>—</>;
  let text: string;
  let tab: FileAuditTab;
  let extra: Record<string, string | null> = {};
  if (fact.kind === "audit_disabled" || fact.kind === "audit_error") {
    tab = "audit-state";
    text = t(fact.kind === "audit_disabled" ? "file-audit.overview.audit_disabled" : "file-audit.screen.audit_failed");
  } else if (fact.kind === "mass" && fact.rule && Object.hasOwn(massLabels, fact.rule) && typeof fact.paths === "number") {
    tab = "mass-operations";
    text = t(massLabels[fact.rule as keyof typeof massLabels], { count: fact.paths });
    extra = { detail_row: fact.id ?? null, path: null, operation: null };
  } else if (fact.kind === "acl" && fact.rule && Object.hasOwn(aclLabels, fact.rule)) {
    tab = "permissions";
    text = t(aclLabels[fact.rule as keyof typeof aclLabels], {
      subject: fact.subject === "S-1-1-0" ? t("file-audit.overview.everyone") : hostText(fact.subject, 256) ?? "—",
      layer: fact.layer === "smb" ? "SMB" : "NTFS",
    });
    if (fact.snapshot && fact.path) extra = { snapshot_id: fact.snapshot, object_path: fact.path, path: fact.path };
  } else return <>—</>;
  const label = fact.severity ? <SeverityBadge severity={fact.severity}
    label={["critical", "high", "medium", "low"].includes(fact.severity)
      ? t(`shell.severity.${fact.severity}` as MessageKey) + " · " + text : text}/> : text;
  return allowed.has("file-audit." + tab) && fileAuditShare(row) ? <a href={hrefFor(tab, row, extra)}>{label}</a> : <>{label}</>;
}

function filteredColumns(view: "mass-operations" | "permission-changes" | "access-denials" | "out-of-hours",
  declared: ReportColumnDto[], open: (row: FileAuditRow) => void): TableColumn<FileAuditRow>[] {
  const column = (key: string, label: MessageKey, value?: TableColumn<FileAuditRow>["value"]): TableColumn<FileAuditRow> =>
    ({ key, label: t(label), value: value ?? (row => row[key]) });
  const server = column("source_name", "file-audit.workspace.server");
  const account = column("employee", "file-audit.screen.who", row => hostText(row.subject_name, 256) || hostText(row.subject_sid, 256));
  const resource: TableColumn<FileAuditRow> = { key: "resource", label: t("file-audit.workspace.resource_path"), wrap: true,
    render: row => <button type="button" className="sli-ds-table__link" onClick={event => { event.stopPropagation(); open(row); }}>
      {resourceName(row)}
    </button> };
  const operation = column("operation", "file-audit.operation", row => fileAuditOperation(row, declared.find(c => c.key === "operation")));
  const time: TableColumn<FileAuditRow> = { ...when("observed_at"), label: t("file-audit.screen.time"), render: row => <FileAuditInterval row={row}/> };
  if (view === "mass-operations") return [
    { ...time, label: t("file-audit.workspace.interval"), render: row => <FileAuditInterval row={{ ...row, aggregate: {
      first_seen_utc: readPath(row, "details.window_start"), last_seen_utc: readPath(row, "details.window_end"),
    } }}/> },
    server, resource, account, operation,
    column("distinct_files", "file-audit.views.paths", row => readPath(row, "details.distinct_files")),
    column("observations", "file-audit.views.observations", row => Array.isArray(row.action_ids) ? row.action_ids.length : undefined),
    column("condition", "file-audit.audit.condition", row => {
      const threshold = readPath(row, "details.threshold"), seconds = readPath(row, "details.window_seconds");
      return typeof threshold === "number" && typeof seconds === "number"
        ? t("file-audit.views.mass_condition", { count: threshold, seconds }) : undefined;
    }),
    { key: "severity", label: t("file-audit.views.importance"), render: row => <SeverityBadge severity={row.severity}/> },
  ];
  if (view === "permission-changes") return [time, account, server, resource, operation,
    column("count", "file-audit.views.observations", row => row.count ?? (row.record_unit === "normalized_action" ? 1 : undefined)),
    { key: "evidence", label: t("file-audit.screen.security_event"), render: row => evidenceRecordNumbers(row)[0]?.value ?? "—" }];
  if (view === "access-denials") return [time, account, column("client_ip", "file-audit.screen.from"), server, resource,
    column("access_mask", "file-audit.views.requested", row => fileMaskLabel(row.access_mask, fileMaskLabels())),
    column("denial_layer", "file-audit.views.layer", row => row.denial_layer === "smb" ? "SMB" : row.denial_layer === "ntfs" ? "NTFS" : undefined),
    operation, { key: "evidence", label: t("file-audit.screen.security_event"), render: row => evidenceRecordNumbers(row)[0]?.value ?? "—" }];
  return [time, server, resource, account, operation, column("schedule", "file-audit.views.schedule", row => {
    const start = readPath(row, "details.calendar.start"), end = readPath(row, "details.calendar.end");
    const zone = readPath(row, "details.calendar.timezone");
    return typeof start === "string" && typeof end === "string" && typeof zone === "string" ? `${start}–${end} · ${zone}` : undefined;
  })];
}

function auditStatus(row: FileAuditRow) {
  const state = row.audit_state;
  if (state === "applying" || state === "restoring" || state === "enabled" || state === "disabled") return t(`file-audit.resources.${state}`);
  if (state === "error") return t("file-audit.screen.audit_failed");
  return t("file-audit.audit.not_collected");
}

function ResourceBatch({ receivedAt }: { receivedAt: FileAuditRow["audit_received_at"] }) {
  const { formatCell } = useDateFormatters();
  return <small>{receivedAt ? t("file-audit.screen.last_batch", { time: formatCell(receivedAt, "datetime") })
    : t("file-audit.screen.no_batch")}</small>;
}

function ResourceDate({ value, href }: { value: unknown; href?: string }) {
  const { formatCell } = useDateFormatters();
  const date = formatCell(value, "datetime");
  return href ? <a href={href}>{date}</a> : <span>{date}</span>;
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
  if (row.audit_state === "enabled") return <>{t("file-audit.audit.entries_verified")}</>;
  if (row.check_pending === true) return <>{t("file-audit.screen.check_pending")}</>;
  if (row.audit_state === "error") {
    const code = typeof row.audit_reason === "string" ? row.audit_reason.split(":")[0] : "";
    const reason = Object.hasOwn(resourceAuditReasons, code) ? resourceAuditReasons[code] : "file-audit.screen.audit_failed";
    return <>{t("file-audit.resources.error", { reason: t(reason) })}</>;
  }
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
      : t(reason)}</>;
  }
  return <>{row.audit_received_at ? formatCell(row.audit_received_at, "datetime") : t("file-audit.audit.not_collected")}</>;
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
