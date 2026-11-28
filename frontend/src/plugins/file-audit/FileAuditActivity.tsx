import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { ReportColumnDto } from "../../api/report-v2-types";
import { withDomain } from "../../app/domain-navigation";
import { columnValue, readPath } from "../../app/report-v2/state";
import { Button, FactList, type TableColumn } from "../../design-system";
import { t } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";
import { formatNumber } from "../../shared/format";
import { FileAuditInterval, evidenceRecordNumbers, fileAuditOperation, hostText, problemNumber } from "./FileAuditCells";
import { fileAuditHref, fileAuditShare, type FileActivityView, type FileAuditRow as Row } from "./report";

type Evidence = { path?: string; role?: string; reference?: string };

const evidenceOf = (row: Row): Evidence[] =>
  Array.isArray(row.evidence) ? row.evidence.filter(item => item && typeof item === "object") : [];
const account = (row: Row) => hostText(row.subject_name, 256) || hostText(row.subject_sid, 256);
const resource = (row: Row) => [hostText(row.source_name, 256), hostText(row.share_name, 256)].filter(Boolean).join(" · ");
const observedSource = (row: Row) => [hostText(row.journal, 64), typeof row.event_code === "number" ? String(row.event_code) : null]
  .filter(Boolean).join(" · ");
const object = (row: Row) => [row.operation === "rename" ? hostText(row.old_path) : undefined, hostText(row.path)].filter(Boolean).join(" → ");
const unobserved = () => t("file-audit.activity.unobserved");

function observations(row: Row) {
  const count = row.count ?? readPath(row, "aggregate.count");
  if (typeof count !== "number") return unobserved();
  const formatted = formatNumber(count);
  return readPath(row, "aggregate.boundary") === "overlap" ? t("file-audit.activity.in_group", { count: formatted }) : formatted;
}

function intervalRow(view: FileActivityView, row: Row): Row {
  return view === "mass-operations" ? { observed_at: row.observed_at, first_seen_utc: readPath(row, "details.window_start"),
    last_seen_utc: readPath(row, "details.window_end") } : row;
}

function condition(row: Row) {
  const threshold = readPath(row, "details.threshold"), seconds = readPath(row, "details.window_seconds");
  return typeof threshold === "number" && typeof seconds === "number"
    ? t("file-audit.activity.condition_value", { count: formatNumber(threshold), seconds: formatNumber(seconds) }) : unobserved();
}

function ProblemLink({ row }: { row: Row }) {
  const id = problemNumber(row);
  return id ? <a href={withDomain('/app/report/security.problems?id=' + id, window.location.search)}
    onClick={event => event.stopPropagation()}>{t("file-audit.screen.problem_number", { id })}</a> : null;
}

export function fileActivityColumns(view: FileActivityView, declared: ReportColumnDto[], selected: string | null,
  rowKey: string, open: (row: Row) => void): TableColumn<Row>[] {
  const time: TableColumn<Row> = { key: "observed_at", label: t("file-audit.workspace.interval"), width: view === "mass-operations" ? "17%" : "21%", render: row => {
    const expanded = selected === String(row[rowKey]);
    return <span className="sli-file-audit__interval">
      <Button variant="ghost" icon={expanded ? "chevron-down" : "chevron-right"} aria-expanded={expanded}
        aria-label={t(expanded ? "file-audit.activity.collapse" : "file-audit.activity.expand")}
        onClick={event => { event.stopPropagation(); open(row); }}/>
      <FileAuditInterval row={intervalRow(view, row)}/>
    </span>;
  } };
  const actor: TableColumn<Row> = { key: "employee", label: t("file-audit.activity.account"), value: account, wrap: true };
  const operation: TableColumn<Row> = { key: "operation", label: t("file-audit.activity.operation"), wrap: true,
    value: row => fileAuditOperation(row, declared.find(column => column.key === "operation")) };
  const path: TableColumn<Row> = { key: "path", label: t("file-audit.activity.object"), width: "34%", wrap: true,
    render: row => object(row) || unobserved() };
  const source: TableColumn<Row> = { key: "event_code", label: t("file-audit.activity.source"), render: row => observedSource(row) || unobserved() };
  const scope: TableColumn<Row> = { key: "resource", label: t("file-audit.activity.server_resource"), value: resource, wrap: true };
  if (view === "mass-operations") return [
    time, scope, actor, operation,
    { key: "distinct_files", kind: "number", label: t("file-audit.activity.distinct_paths"), value: row => readPath(row, "details.distinct_files") },
    { key: "observation_count", kind: "number", label: t("file-audit.activity.observations") },
    { key: "condition", label: t("file-audit.activity.condition"), value: condition },
    { key: "problem", label: t("file-audit.screen.problem"), render: row => row.problem_id ? <ProblemLink row={row}/> : "—" },
  ];
  if (view === "access-denials") return [
    time, actor,
    { key: "client_ip", label: t("file-audit.activity.client"), value: row => hostText(row.client_ip, 64) },
    scope, path,
    { key: "access_mask", label: t("file-audit.activity.requested_access"), render: row =>
      typeof row.access_mask === "number" ? "0x" + row.access_mask.toString(16).toUpperCase() : unobserved() },
    { key: "denial_layer", label: t("file-audit.activity.layer"), value: row =>
      row.denial_layer === "smb" ? "SMB" : row.denial_layer === "ntfs" ? "NTFS" : unobserved() },
    { key: "outcome", label: t("file-audit.activity.outcome"), value: () => t("file-audit.screen.access_denied") },
    source,
  ];
  if (view === "out-of-hours") return [
    time, actor, operation, scope, path,
    { key: "local_time", label: t("file-audit.activity.local_time"), value: row => {
      const zone = hostText(readPath(row, "details.timezone"), 128);
      const at = hostText(row.observed_at, 64);
      return at && zone ? formatDateTime(at, zone, { seconds: true }) : unobserved();
    } },
    { key: "schedule", label: t("file-audit.activity.schedule"), value: schedule },
  ];
  return [
    time, { ...actor, width: "18%" }, { ...operation, width: "15%" }, { ...path, width: "21%" },
    { key: "count", kind: "number", label: t("file-audit.activity.observations"), width: "12%", render: observations },
    { ...source, width: "13%" },
  ];
}

function schedule(row: Row) {
  const zone = hostText(readPath(row, "details.timezone") ?? readPath(row, "details.calendar.timezone"), 128);
  return zone ? t("file-audit.activity.working_hours", { zone }) : unobserved();
}

function FileAuditActionLinks({ row, params, session, canPermissions, back }: {
  row: Row; params: URLSearchParams; session: string; canPermissions: boolean; back: string;
}) {
  const evidence = evidenceOf(row);
  const reference = (evidence.find(item => item.role === "primary") ?? evidence[0])?.reference;
  const eventId = typeof reference === "string" ? /^event_cold_facts:([1-9]\d{0,18})$/.exec(reference)?.[1] : undefined;
  const saved = useQuery({ queryKey: ["file-audit", "saved-record", session, eventId], queryFn: () => api.eventAvailable(eventId!),
    enabled: Boolean(eventId), retry: false });
  const share = fileAuditShare(row);
  const path = hostText(row.path);
  const scope = new URLSearchParams([...params].filter(([key]) =>
    ["period", "from", "to", "tz", "source_kind", "file_server_domain", "limit"].includes(key)));
  if (share && path) {
    scope.set("share", share);
    scope.set("path", path);
    scope.set("include_nested", "false");
    scope.set("view", "objects");
  }
  const permissions = useQuery({
    queryKey: ["file-audit", "object-links", session, scope.toString()],
    queryFn: async () => {
      const page = await api.reportV2Data("file-audit.permissions", scope);
      const snapshot = page.items.find(item => item.path === path || hostText(item.path)?.toLowerCase() === path?.toLowerCase())?.snapshot_id;
      if (typeof snapshot !== "string") return null;
      const detail = await api.reportV2Detail("file-audit.permissions", snapshot, scope).catch(() => undefined);
      if (!detail || detail.state === "denied" || detail.state === "error") return null;
      const prior = detail.collections?.snapshots?.find(item => item.id !== snapshot)?.id;
      if (typeof prior !== "string") return { snapshot };
      const compare = new URLSearchParams(scope);
      compare.set("compare_snapshot_id", prior);
      const compared = await api.reportV2Detail("file-audit.permissions", snapshot, compare).catch(() => undefined);
      const comparison = (compared as (typeof compared & { detail?: { comparison?: { state?: string } } }))?.detail?.comparison;
      return comparison?.state === "available" ? { snapshot, prior } : { snapshot };
    },
    enabled: Boolean(canPermissions && share && path), retry: false,
  });
  const target = (snapshot: string, prior?: string) => withDomain(fileAuditHref("permissions", scope,
    { ...row, snapshot_id: snapshot }, { object_path: path!, return_to: back,
      ...(prior ? { object_tab: "comparison", compare_snapshot_id: prior } : {}) }), window.location.search);
  if (!saved.data && !permissions.data && !problemNumber(row)) return null;
  return <div className="sli-file-audit__segments">
    {saved.data ? <a href={withDomain("/app/events/" + eventId, window.location.search)}>{t("file-audit.activity.saved_record")}</a> : null}
    {permissions.data ? <a href={target(permissions.data.snapshot)}>{t("file-audit.activity.object_permissions")}</a> : null}
    {permissions.data?.prior ? <a href={target(permissions.data.snapshot, permissions.data.prior)}>{t("file-audit.activity.compare")}</a> : null}
    <ProblemLink row={row}/>
  </div>;
}

export function FileAuditActivityDetails({ view, row, declared, params, session, canPermissions, back }: {
  view: FileActivityView; row: Row; declared: ReportColumnDto[]; params: URLSearchParams | null;
  session: string; canPermissions: boolean; back: string;
}) {
  if (view === "mass-operations") {
    const paths = [...new Set(evidenceOf(row).flatMap(item => hostText(item.path) || []))];
    return <div className="sli-file-audit__ace-details">
      <FactList facts={[
        { label: t("file-audit.workspace.interval"), value: <FileAuditInterval row={intervalRow(view, row)}/> },
        { label: t("file-audit.activity.condition"), value: condition(row) },
        { label: t("file-audit.activity.observations"), value: typeof row.observation_count === "number" ? formatNumber(row.observation_count) : unobserved() },
        { label: t("file-audit.activity.paths"), value: paths.length ? <ul>{paths.map(path => <li key={path}>{path}</li>)}</ul> : unobserved() },
      ]}/>
    </div>;
  }
  const name = account(row), sid = hostText(row.subject_sid, 256);
  const [records] = evidenceRecordNumbers(row);
  const server = [hostText(row.source_name, 256), observedSource(row)].filter(Boolean).join(" · ");
  return <div className="sli-file-audit__ace-details" data-layout="columns">
    <FactList facts={[
      { label: t("file-audit.screen.path"), value: object(row) || unobserved() },
      { label: t("file-audit.activity.subject"), value: name && sid && name !== sid ? `${name} · ${sid}` : name ?? unobserved() },
      { label: t("file-audit.workspace.interval"), value: <><FileAuditInterval row={row}/>
        {typeof (row.count ?? readPath(row, "aggregate.count")) === "number" ? <> · {t("file-audit.activity.observation_value", { count: observations(row) })}</> : null}</> },
      { label: t("file-audit.workspace.server"), value: <>
        {server || unobserved()}
        {records ? <div title={records.label}>{records.value}</div> : null}
      </> },
      ...declared.filter(column => view === "access-denials" && column.key === "denial_layer")
        .map(column => ({ label: column.label, value: String(columnValue(column, row) ?? unobserved()) })),
    ]}/>
    {params ? <FileAuditActionLinks row={row} params={params} session={session} canPermissions={canPermissions} back={back}/> : <ProblemLink row={row}/>}
  </div>;
}
