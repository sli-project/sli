import { useTimeZone } from "../../shared/time-zone";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { useState } from "react";
import { DataTable, formatCell, type TableColumn } from "../../design-system";
import { ReviewList, type ReviewItem } from "../../design-system/ReviewList";
import type { ReportColumnDto, ReportResultDto } from "../../api/report-v2-types";
import { t } from "../../i18n";
import { tableColumns } from "../../app/report-v2/DetailSection";
import { columnValue } from "../../app/report-v2/state";
import { AgentStatus, DnsIp, dnsColumnLabel } from "./ReportAdditions";
import { ComputerGpoPlan } from "./GpoPlan";

type Row = Record<string, unknown>;
type ComputerPreview = Row & { name: string | null; domain_name: string | null; computer_type: string | null };
type Check = {
  key: string; title: string; severity: string; severityText: string; status: string;
  total: number | null; newCount: number | null; remaining: number;
  why: string; action: string; observed: string | null; actor: string | null;
  objects: ComputerPreview[];
};
const text = (value: unknown) => typeof value === "string" && value.trim() ? value : null;
const count = (value: unknown) => typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;

export function computerSummary(result?: ReportResultDto) {
  if (!result) return undefined;
  const population = count(result.coverage.population) ?? count(result.metrics.find((metric) => metric.key === "all")?.value);
  const affected = count(result.coverage.affected_objects) ?? count(result.metrics.find((metric) => metric.key === "attention")?.value);
  return t("reports.ad.computers.summary", { count: population ?? t("table.noValue"),
    affected: affected ?? t("table.noValue") });
}

export function computerTableColumns(columns: ReportColumnDto[], onSelect: (row: Row) => void, rows: Row[] = [], timeZone?: string): TableColumn<Row>[] {
  const inventory = columns.some((column) => column.key === "laps_state");
  return tableColumns(columns, timeZone).map((column) => ({ ...column,
    render: column.render ?? ((row: Row) => computerFactValue(columns.find((item) => item.key === column.key)!, row, timeZone)),
    // Both desktop names and mobile rows open the same overlay.
    ...(column.key === "display_name" ? { render: (row: Row) => <><button type="button" className="sli-ds-button" data-variant="ghost" onClick={(event) => { event.stopPropagation(); onSelect(row); }}>{text(row.display_name) ?? t("table.noValue")}</button><AgentStatus row={row} compact/><div className="sli-ds-muted">{text(row.domain_name) ?? t("table.noValue")}</div></> } : {}),
    ...(column.key === "computer_type" ? { label: t("reports.ad.computers.role"), render: (row: Row) => computerRole(row.computer_type) } : {}),
    ...(column.key === "operating_system" ? { render: (row: Row) => text(row.operating_system) && !["unknown", "none", "null"].includes(String(row.operating_system).toLowerCase()) ? String(row.operating_system) : t("table.noValue") } : {}),
    ...(column.key === "ip_addresses" ? { label: dnsColumnLabel(rows, timeZone) } : {}),
    hiddenByDefault: inventory ? !["display_name", "computer_type", "operating_system", "ou_path", "last_logon_utc", "laps_state", "ip_addresses", "sli_agent"].includes(column.key) : column.hiddenByDefault,
    mobile: ["display_name", "computer_type", "change_type"].includes(column.key),
  }));
}

export function computerFactValue(column: ReportColumnDto, row: Row, timeZone?: string) {
  if (column.key === "ip_addresses") return <DnsIp row={row}/>;
  if (column.key === "sli_agent") return <AgentStatus row={row}/>;
  if (column.key === "computer_type") return computerRole(row.computer_type);
  const value = columnValue(column, row);
  return value === null || value === undefined || value === "" || (typeof value === "string" && ["unknown", "none", "null"].includes(value.toLowerCase()))
    ? t("table.noValue") : formatCell(value, column.kind === "state" || column.kind === "code" ? "text" : column.kind, timeZone);
}

export function ComputerReasons({ row }: { row: Row }) {
  const reasons = (Array.isArray(row.reasons) ? row.reasons : []).filter((reason): reason is Row => Boolean(reason) && typeof reason === "object");
  return <section className="sli-ds-report__views" aria-label={t("reports.ad.computers.reasons")}>
    {row.sli_agent && typeof row.sli_agent === "object" && (row.sli_agent as Row).state === "absent" ? <ComputerGpoPlan rows={[row]}/> : null}
    <h3 className="sli-ds-section-title">{t("reports.ad.computers.reasons")}</h3>
    {reasons.length ? reasons.map((reason, index) => <section className="sli-ds-panel" key={String(reason.code ?? index)}>
      <h4 className="sli-ds-section-title">{text(reason.label) ?? t("table.noValue")}</h4>
      <p><strong>{t("reports.ad.checks.column.why")}: </strong>{text(reason.qualification) ?? text(reason.observed) ?? t("table.noValue")}</p>
      <p><strong>{t("reports.ad.checks.column.action")}: </strong>{text(reason.next_action) ?? t("table.noValue")}</p>
    </section>) : <p className="sli-ds-muted">{t("reports.ad.computers.no_recorded_reasons")}</p>}
  </section>;
}


export function computerRole(value: unknown) {
  return value === "domain_controller" ? t("reports.v2.ad.computers.v6.columns.computer_type.labels.domain_controller")
    : value === "server" ? t("reports.v2.ad.computers.v6.columns.computer_type.labels.server")
    : value === "workstation" ? t("reports.v2.ad.computers.v6.columns.computer_type.labels.workstation")
    : t("table.noValue");
}

/** Only saved agent facts enter this view model; null counts are never zero. */
function checkModel(row: Row): Check {
  const change = row.change && typeof row.change === "object" ? row.change as Row : {};
  return {
    key: text(row.key) ?? String(row.id), title: text(row.title) ?? t("table.noValue"),
    severity: text(row.severity) ?? "unknown", severityText: text(row.severity_text) ?? t("table.noValue"),
    status: row.status === "no_comparison" ? t("reports.ad.checks.status.no_comparison")
      : row.status === "not_evaluated" || row.status_text === t("reports.ad.checks.status.not_evaluated")
      ? t("table.noValue") : text(row.status_text) ?? t("table.noValue"),
    total: count(row.total), newCount: count(row.new_count),
    remaining: count(row.remaining_objects) ?? 0,
    why: text(row.why) ?? t("table.noValue"), action: text(row.action) ?? t("table.noValue"),
    observed: text(row.last_seen_utc), actor: text(change.actor),
    objects: (Array.isArray(row.objects) ? row.objects : []).filter((obj): obj is Row => Boolean(obj) && typeof obj === "object")
      .map((obj) => ({ ...obj, name: text(obj.name), domain_name: text(obj.domain_name), computer_type: text(obj.computer_type) })),
  };
}

export function ComputerChecks({ result, onSelect, onInventory }: {
  result?: ReportResultDto; onSelect: (row: Row) => void; onInventory: () => void;
}) {
  const { formatDateTime } = useDateFormatters();
  const { timeZone } = useTimeZone();
  const [severity, setSeverity] = useState("");
  const checks = (result?.items ?? []).filter((row) => row.section !== "not_evaluated").map(checkModel)
    .filter((check) => check.status !== t("table.noValue") || check.total !== null || check.newCount !== null);
  const severities = new Map(checks.map((check) => [check.severity, check.severityText]));
  const item = (check: Check): ReviewItem => {
    const columns: TableColumn<ComputerPreview>[] = [
      { key: "name", label: t("reports.v2.ad.computers.v6.columns.display_name.label"), render: (obj) => <>
        <button type="button" className="sli-ds-button" data-variant="ghost" onClick={() => onSelect({ ...obj, display_name: obj.name,
          account_state: obj.enabled === true ? "enabled" : obj.enabled === false ? "disabled" : "unknown",
          reasons: [{ label: check.title, observed: obj.observed_at_utc, qualification: check.why, next_action: check.action }] })}>{obj.name ?? t("table.noValue")}</button>
        <div className="sli-ds-muted">{obj.domain_name ?? t("table.noValue")}</div>
        <AgentStatus row={obj} compact/>
      </> },
      { key: "computer_type", label: t("reports.ad.computers.role"), render: (obj) => computerRole(obj.computer_type) },
      { key: "dns_ip", label: dnsColumnLabel(check.objects, timeZone), render: (obj) => <DnsIp row={obj}/>, mobile: false },
      { key: "sli_agent", label: t("reports.ad.additions.agent_label"), render: (obj) => <AgentStatus row={obj}/>, mobile: false },
      { key: "observed_at_utc", label: t("reports.ad.computers.last_seen"), kind: "datetime", mobile: false },
    ];
    return {
      key: check.key, title: check.title, severity: check.severityText,
      tone: check.severity === "high" ? "danger" : check.severity === "medium" ? "warning" : "neutral",
      status: check.status, total: check.total, newCount: check.newCount,
      objects: null,
      detail: <>
        <p><strong>{t("reports.ad.checks.column.why")}: </strong>{check.why}</p>
        <p><strong>{t("reports.ad.checks.column.action")}: </strong>{check.action}</p>
        {check.key === "no_sli_agent" ? <ComputerGpoPlan rows={check.objects}/> : null}
        <p className="sli-ds-muted">{t("reports.ad.computers.last_seen")}: {formatDateTime(check.observed)}
          {check.key !== "no_sli_agent" ? <> · {t("reports.ad.computers.actor")}: {check.actor ?? t("table.noValue")}</> : null}</p>
        {check.objects.length ? <DataTable caption={check.title} columns={columns} rows={check.objects} rowKey={(obj) => `${obj.domain_id}:${obj.name}`} stickyHeader={false}/> : null}
        {check.remaining > 0 ? <button className="sli-ds-button" type="button" onClick={onInventory}>{t("reports.ad.computers.inventory")}</button> : null}
      </>,
    };
  };
  const activeSeverity = severities.has(severity) ? severity : "";
  return <>
    {severities.size > 1 ? <label className="sli-ds-field">{t("reports.ad.checks.column.severity")}
      <select value={activeSeverity} onChange={(event) => setSeverity(event.target.value)}>
        <option value="">{t("filters.any")}</option>
        {[...severities].map(([value, label]) => <option key={value} value={value}>{label}</option>)}
      </select>
    </label> : null}
    <ReviewList compact items={checks.filter((check) => !activeSeverity || check.severity === activeSeverity).map(item)}/>
  </>;
}
