import { useTimeZone } from "../../shared/time-zone";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { memo } from "react";
import type { ReportColumnDto, ReportOption } from "../../api/report-v2-types";
import { DataTable, SeverityBadge, formatCell, type TableColumn } from "../../design-system";
import { isSeverity } from "../../design-system/SeverityBadge";
import { t, type MessageKey } from "../../i18n";
import { formatNumber } from "../../shared/format";
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

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };

export function userDeviations(row: Row) {
  const reviewReasons = objects(row.review_reasons);
  const reasons = reviewReasons.length ? reviewReasons : objects(row.reasons);
  const confirmed = reasons.flatMap((reason) => {
    const key = String(reason.key);
    const days = count(object(reason.policy).threshold_days);
    const label = reviewReasons.length ? text(reason.label)
      : days !== null && key === "password_age" ? t("reports.ad.users.deviation.password_age", { days })
      : days !== null && key === "inactive_threshold" ? t("reports.ad.users.deviation.inactive", { days })
      : Object.hasOwn(deviations, key) ? t(deviations[key]) : text(reason.label);
    return label ? [{ key, label, severity: reason.severity }] : [];
  });
  const rank = (severity: unknown) => isSeverity(severity) ? severityOrder[severity] : Number.POSITIVE_INFINITY;
  if (confirmed.length) return confirmed.sort((a, b) => rank(a.severity) - rank(b.severity));
  const label = text(row.reason_text) ?? (row.password_never_expires === true ? t("reports.ad.users.list.password_no_expiry") : null);
  return label ? [{ key: "", label, severity: row.severity }] : [];
}

export function UserStateMark({ enabled }: { enabled: boolean }) {
  return <span aria-hidden="true" style={{ color: enabled ? "var(--sli-success)" : "var(--sli-text-muted)" }}>{enabled ? "●" : "⊘"}</span>;
}

export function userTableColumns(columns: ReportColumnDto[], onSelect: (row: Row, tab?: string) => void, timeZone?: string, review = false): TableColumn<Row>[] {
  const order = review ? ["name", "privilege_basis", "activity", "reason"] : ["name", "privilege_basis", "department", "ou", "activity", "last_workplace", "password_last_set", "groups", "reason"];
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
        const [reason, ...otherReasons] = userDeviations(row);
        if (!reason) return missing();
        const severity = isSeverity(reason.severity) ? reason.severity : row.severity;
        return <>{isSeverity(severity) ? <><SeverityBadge severity={severity}/> </> : null}
          <span>{reason.label}</span>{otherReasons.length ? <> <button type="button" className="sli-ds-link-button"
            aria-label={t("reports.ad.users.list.more_deviations", { count: otherReasons.length })}
            onClick={(event) => { event.stopPropagation(); onSelect(row, "account"); }}>+{formatNumber(otherReasons.length)}</button></> : null}</>;
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
      const status = typeof row.enabled === "boolean" ? t(row.enabled ? "reports.ad.users.card.enabled" : "reports.ad.users.card.disabled") : undefined;
      return <>{typeof row.enabled === "boolean" ? <><UserStateMark enabled={row.enabled}/> </> : null}
        <button type="button" className="sli-ds-link-button" aria-description={status} title={status}
          onClick={(event) => { event.stopPropagation(); onSelect(row); }}>{account}</button>
        {displayName ? <> / {displayName}</> : null}</>;
    }}];
  });
}


export function UserCheckFilters({ options, selected, total, onChange }: {
  options: ReportOption[]; selected: string; total?: number; onChange: (check: string) => void;
}) {
  const checks = options.filter(({ count }) => typeof count === "number" && count > 0);
  if (!checks.length && !selected) return null;
  return <div className="sli-ds-header__actions" role="group" aria-label={t("reports.v2.ad.users.v2.params.check.label")}>
    <button type="button" className="sli-ds-chip" aria-pressed={!selected} onClick={() => onChange("")}>
      {t("reports.ad.users.list.all")}{typeof total === "number" ? " " + formatNumber(total) : ""}
    </button>
    {checks.map(({ value, label, count }) => <button key={value} type="button" className="sli-ds-chip" aria-pressed={value === selected}
      onClick={() => onChange(value === selected ? "" : value)}>{label} {formatNumber(count!)}</button>)}
  </div>;
}

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
  return rows.length ? <DataTable caption={title} columns={mapped} rows={rows} rowKey={(row) => JSON.stringify(row)} onRowClick={onSelect} wrapCells="all" {...paging}/>
    : <p>{missing()}</p>;
});
